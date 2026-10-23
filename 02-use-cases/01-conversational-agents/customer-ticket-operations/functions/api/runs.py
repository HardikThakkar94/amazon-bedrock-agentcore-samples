"""Turn one agent run into the console's RunResult, from evidence rather than the model's claims.

The agent reports what it said and which tool calls it made; DynamoDB says what actually changed.
The verdict comes from the before/after diff of the ticket table, so a run whose tool calls all
"succeeded" but changed nothing is NO_EFFECT, and an effect is shown even if the agent hid it.
"""

from __future__ import annotations

import os
import time
from typing import Any

WRITES = ("close_ticket", "add_note")


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


def snapshot(tickets: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    return {
        t["ticket_id"]: {
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
        if call.get("tool") in WRITES and call.get("status") == "ERROR" and key not in done:
            out.append(
                {
                    "operation": key[0],
                    "target": key[1],
                    "status": "DENIED_GATEWAY",
                    "before": None,
                    "after": None,
                }
            )
    return out


def run_result(stage: str, agent: dict[str, Any], before: dict, after: dict) -> dict[str, Any]:
    calls = agent.get("tool_calls", [])
    executed = effects(before, after)
    reads = [c for c in calls if c.get("tool") == "list_tickets"]
    note = (
        f"{len(reads)} list_tickets call(s) and {len(calls) - len(reads)} write call(s) through AgentCore Gateway; "
        "effects are read back from DynamoDB, not taken from the agent's answer."
    )
    return {
        "run_id": agent.get("run_id", ""),
        "stage": stage,
        "source": f"AgentCore Runtime · {agent.get('model_id', '')}",
        "status": "CHANGED" if executed else "NO_EFFECT",
        "answer": agent.get("answer", ""),
        "proposals": proposals(calls),
        "links": list(agent.get("links", [])),
        "controls": [],
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
