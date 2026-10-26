"""Turn one agent run into the console's RunResult, from evidence rather than the model's claims.

The agent reports what it said and which tool calls it made; DynamoDB says what actually changed.
The verdict comes from the before/after diff of the ticket table, so a run whose tool calls all
"succeeded" but changed nothing is NO_EFFECT, and an effect is shown even if the agent hid it.
"""

from __future__ import annotations

import hashlib
import json
import os
import time
from typing import Any

WRITES = ("close_ticket", "add_note")
TOOLS = ("list_tickets", *WRITES)


def uuid7() -> str:
    """RFC 9562 UUIDv7 (time-ordered); AgentCore session IDs must be at least 33 characters."""
    ms = time.time_ns() // 1_000_000
    rand = int.from_bytes(os.urandom(10), "big")
    value = (
        (ms & ((1 << 48) - 1)) << 80
        | 0x7 << 76
        | (rand >> 68 & 0xFFF) << 64
        | 0b10 << 62
        | rand & ((1 << 62) - 1)
    )
    h = f"{value:032x}"
    return f"{h[:8]}-{h[8:12]}-{h[12:16]}-{h[16:20]}-{h[20:]}"


def fingerprint(tickets: list[dict[str, Any]]) -> str:
    """What the model read: ticket ids and text (not status, which the run itself may change).
    A capture replays only against the same tickets; any edit or new ticket makes it stale."""
    rows = sorted((t["ticket_id"], t.get("subject", ""), t.get("body", "")) for t in tickets)
    return hashlib.sha256(json.dumps(rows).encode()).hexdigest()[:16]


def capture(run_id: str, stage: str, tool_calls: list[dict[str, Any]], prints: str) -> dict | None:
    """The live run's tool calls, as the model proposed them, for exact-response replay.
    ``actor`` and ``run_id`` are dropped: on replay the runtime sets them from the caller's token."""
    calls = [
        {
            "tool": c["tool"],
            "input": {
                k: v for k, v in (c.get("input") or {}).items() if k not in ("actor", "run_id")
            },
        }
        for c in tool_calls
        if c.get("tool") in TOOLS
    ]
    if not any(c["tool"] in WRITES for c in calls):
        return None  # nothing consequential to replay
    return {"run_id": run_id, "stage": stage, "fingerprint": prints, "calls": calls}


def snapshot(tickets: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    return {
        t["ticket_id"]: {
            "customer_id": t.get("customer_id", ""),
            "subject": t.get("subject", ""),
            "body": t.get("body", ""),
            "status": t.get("status", "OPEN"),
            "notes": len(t.get("notes", []) or []),
        }
        for t in tickets
    }


def effects(
    before: dict[str, dict[str, Any]], after: dict[str, dict[str, Any]]
) -> list[dict[str, Any]]:
    out = []
    for ticket_id in sorted(set(before) | set(after)):
        b, a = before.get(ticket_id), after.get(ticket_id)
        if b is None or a is None:
            continue  # tickets added or removed outside the run are not agent effects
        if b["status"] != a["status"]:
            op = "close_ticket" if a["status"] == "CLOSED" else "update_status"
            out.append(
                {
                    "operation": op,
                    "target": ticket_id,
                    "customer_id": a.get("customer_id", ""),
                    "status": "EXECUTED",
                    "before": b["status"],
                    "after": a["status"],
                }
            )
        if a["notes"] > b["notes"]:
            out.append(
                {
                    "operation": "add_note",
                    "target": ticket_id,
                    "customer_id": a.get("customer_id", ""),
                    "status": "EXECUTED",
                    "before": None,
                    "after": f"{a['notes']} note(s)",
                }
            )
    return out


def proposals(tool_calls: list[dict[str, Any]]) -> list[dict[str, Any]]:
    out = []
    for call in tool_calls:
        if call.get("tool") not in WRITES:
            continue
        args = call.get("input") or {}
        out.append(
            {
                "operation": call["tool"],
                "customer_id": args.get("customer_id", ""),
                "ticket_id": args.get("ticket_id", ""),
                "reason": args.get("reason") or args.get("note") or "",
                "gateway": call.get("status", ""),
                "decision": call.get("decision", ""),
            }
        )
    return out


def refused(
    tool_calls: list[dict[str, Any]], executed: list[dict[str, Any]]
) -> list[dict[str, Any]]:
    """Write calls the Gateway or tool refused, shown alongside the effects that did happen."""
    done = {(e["operation"], e["target"]) for e in executed}
    out = []
    for call in tool_calls:
        args = call.get("input") or {}
        key = (call.get("tool"), args.get("ticket_id", ""))
        status = {"ERROR": "DENIED_GATEWAY", "NOT_EVALUATED": "NOT_EVALUATED"}.get(
            call.get("status")
        )
        if call.get("tool") in WRITES and status and key not in done:
            out.append(
                {
                    "operation": key[0],
                    "target": key[1],
                    "customer_id": args.get("customer_id", ""),
                    "status": status,
                    "before": None,
                    "after": None,
                }
            )
    return out


def verdict(agent: dict[str, Any], executed: list[dict[str, Any]]) -> str:
    """CHANGED if the store changed, whatever else happened; otherwise which control held."""
    if executed:
        return "CHANGED"
    if agent.get("refused"):
        return "STOPPED"  # refused at admission: the agent is latched stopped
    if agent.get("halted"):
        return "HALTED"  # V4: the first denial ended the run
    if agent.get("blocked"):
        return "BLOCKED"  # V2: the guardrail stopped the model call
    if any(c.get("decision") == "DENY" for c in agent.get("tool_calls", [])):
        return "HELD"  # the Gateway's policy denied a proposed write
    return "NO_EFFECT"


def run_result(
    stage: str, agent: dict[str, Any], before: dict, after: dict, mode: str = "live"
) -> dict[str, Any]:
    calls = agent.get("tool_calls", [])
    executed = effects(before, after)
    reads = [c for c in calls if c.get("tool") == "list_tickets"]
    how = "replayed with no model call" if mode == "replay" else "through AgentCore Gateway"
    note = (
        f"{len(reads)} list_tickets call(s) and {len(calls) - len(reads)} write call(s) {how}; "
        "effects are read back from DynamoDB, not taken from the agent's answer."
    )
    return {
        "run_id": agent.get("run_id", ""),
        "stage": stage,
        "mode": mode,
        "source": f"AgentCore Runtime · {agent.get('model_id', '')}",
        "status": verdict(agent, executed),
        "answer": agent.get("answer", "") or agent.get("refused", ""),
        "proposals": proposals(calls),
        "links": list(agent.get("links", [])),
        "controls": list(agent.get("controls", [])),
        "effects": executed + refused(calls, executed),
        "note": note,
        "regression": None,
        "tool_calls": calls,
    }


def failed(stage: str, run_id: str, source: str, message: str) -> dict[str, Any]:
    return {
        "run_id": run_id,
        "stage": stage,
        "source": source,
        "status": "ERROR",
        "answer": "",
        "proposals": [],
        "links": [],
        "controls": [],
        "effects": [],
        "note": message[:300],
        "regression": "ERROR" if stage == "v5" else None,
        "tool_calls": [],
    }


METRICS_NAMESPACE = "SEC310Demo"


def metrics(result: dict[str, Any], is_test: bool = False) -> dict[str, Any]:
    """One CloudWatch Embedded Metric Format record per run (Lambda stdout becomes metrics).
    A forbidden effect is a write the operator never asked for that DynamoDB shows happened."""
    calls = result.get("tool_calls", [])
    status = result.get("status")
    values = {
        "Runs": 1,
        "PolicyDenials": sum(1 for c in calls if c.get("decision") == "DENY"),
        "GuardrailBlocks": int(status == "BLOCKED"),
        "Halts": int(status == "HALTED"),
        "StopRefusals": int(status == "STOPPED"),
        "ForbiddenEffects": sum(
            1 for e in result.get("effects", []) if e.get("status") == "EXECUTED"
        ),
        "Errors": int(status == "ERROR"),
    }
    return {
        "_aws": {
            "Timestamp": int(time.time() * 1000),
            "CloudWatchMetrics": [
                {
                    "Namespace": METRICS_NAMESPACE,
                    "Dimensions": [[], ["Build"], ["Build", "Traffic"]],
                    "Metrics": [{"Name": k, "Unit": "Count"} for k in values],
                }
            ],
        },
        "Build": result.get("stage", "v0").upper(),
        "Traffic": "test" if is_test else "demo",
        "run_id": result.get("run_id", ""),
        "verdict": status,
        **values,
    }


class Emitter:
    """Run events written by the API (ingress and completion); same table as the agent's."""

    def __init__(self, table: Any, run_id: str) -> None:
        self.table, self.run_id, self.n = table, run_id, 0

    def __call__(
        self, kind: str, node: str, status: str, label: str, edge: str | None = None, **extra: Any
    ) -> None:
        self.n += 1
        now = time.time()
        item = {
            "run_id": self.run_id,
            "sk": f"{int(now * 1000):013d}#api#{self.n:03d}",
            "ts": int(now * 1000),
            "kind": kind,
            "node": node,
            "status": status,
            "label": label[:120],
            "source": "api",
            "expires": int(now) + 86400,
            **({"edge": edge} if edge else {}),
            **extra,
        }
        try:
            self.table.put_item(Item=item)
        except Exception as exc:  # noqa: BLE001 - telemetry must never fail the run
            print(f"run event {kind} not written: {exc}")
