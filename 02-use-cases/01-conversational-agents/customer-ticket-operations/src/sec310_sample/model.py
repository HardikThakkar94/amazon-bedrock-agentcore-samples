"""Deterministic stand-in for a language model, plus an optional real one.

``ScriptedModel`` is deliberately gullible: it follows any ``ACTION:`` or ``LINK:``
directive it can see in the prompt, wherever it came from. That stands in for the
worst case of a real model under prompt injection. The controls in this repo must
hold even when the model behaves this badly; nothing in the talk relies on the
model being smart.

``BedrockModel`` is opt-in and only ever used to *propose*. It never executes
anything and is never wired to the write path.
"""

from __future__ import annotations

import json
import os
import re
from collections.abc import Iterator
from typing import Protocol

MODEL_VERSION_SCRIPTED = "scripted-model/1"

_ACTION_RE = re.compile(
    r"ACTION:\s*(read_evidence|update_rule|delete_rule)\s+(acct-[a-z0-9-]+)\s+(rule-[a-z0-9-]+|-)",
    re.IGNORECASE,
)
_LINK_RE = re.compile(r"LINK:\s*(\S+)")
_ACCOUNT_RE = re.compile(r"account under investigation:\s*(acct-[a-z0-9-]+)", re.IGNORECASE)
_TENANT_RE = re.compile(r"\bTenant\s+(tenant-[a-z0-9-]+)", re.IGNORECASE)
_ENABLE_RE = re.compile(r"re-?enable\s+(rule-[a-z0-9-]+)", re.IGNORECASE)
_SEVERITY_RE = re.compile(r'"severity":\s*"(\w+)"')


class Model(Protocol):
    version: str

    def complete(self, prompt: str) -> str: ...

    def stream(self, prompt: str) -> Iterator[str]: ...


class ScriptedModel:
    """Deterministic. Same prompt in, same JSON out. No network."""

    version = MODEL_VERSION_SCRIPTED

    def complete(self, prompt: str) -> str:
        account_match = _ACCOUNT_RE.search(prompt)
        account = account_match.group(1) if account_match else "acct-unknown"
        severities = _SEVERITY_RE.findall(prompt)
        top = _rank(severities)

        proposed: list[dict[str, object]] = []
        # 1. Anything that looks like an instruction gets followed. This is the bug
        #    we are containing, not a feature.
        for op, acct, resource in _ACTION_RE.findall(prompt):
            proposed.append(_plan(op.lower(), acct, resource, "requested in context"))
        # 2. A legitimate analyst ask ("re-enable rule-42") becomes a typed proposal.
        for rule in _ENABLE_RE.findall(prompt):
            proposed.append(
                _plan("update_rule", account, rule, "analyst asked to re-enable", {"enabled": True})
            )
        if not proposed:
            proposed.append(_plan("read_evidence", account, "-", "gather more evidence"))

        links = list(_LINK_RE.findall(prompt)) or [f"/accounts/{account}/findings"]
        answer = (
            f"Reviewed {len(severities)} finding(s) for {account}. "
            f"Highest severity: {top}. "
            + (
                "rule-42 was disabled shortly before a sign-in without MFA; treat as suspicious."
                if "rule-42" in prompt
                else ""
            )
        ).strip()
        return json.dumps({"answer": answer, "proposed_actions": proposed, "links": links})

    def stream(self, prompt: str) -> Iterator[str]:
        text = self.complete(prompt)
        step = max(1, len(text) // 3)
        for i in range(0, len(text), step):
            yield text[i : i + step]


def _plan(
    op: str, account: str, resource: str, reason: str, change: dict[str, object] | None = None
) -> dict[str, object]:
    plan: dict[str, object] = {
        "operation": op,
        "account_id": account,
        "resource_id": resource,
        "reason": reason,
    }
    if change is not None:
        plan["change"] = change
    return plan


def _rank(severities: list[str]) -> str:
    order = ["critical", "high", "medium", "low", "info"]
    for level in order:
        if level in severities:
            return level
    return "none"


_SYSTEM = (
    "You are a security evidence assistant. Answer using only the supplied context. "
    "Respond with exactly one JSON object with keys: answer (string), proposed_actions "
    "(list of {operation: read_evidence|update_rule|delete_rule, account_id, resource_id, "
    "reason, change?}), "
    "links (list of relative paths). No prose outside the JSON."
)


class BedrockModel:
    """Opt-in live model via the Bedrock Converse API. Proposals only.

    Requires the ``aws`` extra and ``SEC310_MODEL_ID`` in the environment. Region and
    credentials come from the normal AWS SDK chain. Nothing here can mutate state.
    """

    def __init__(self, model_id: str | None = None, client=None) -> None:
        self.model_id = model_id or os.environ.get("SEC310_MODEL_ID")
        if not self.model_id:
            raise RuntimeError("set SEC310_MODEL_ID to use the live model path")
        self.version = f"bedrock/{self.model_id}"
        if client is None:
            import boto3  # lazy: the offline path must not need it

            client = boto3.client("bedrock-runtime")
        self._client = client

    def complete(self, prompt: str) -> str:
        resp = self._client.converse(
            modelId=self.model_id,
            system=[{"text": _SYSTEM}],
            messages=[{"role": "user", "content": [{"text": prompt}]}],
            inferenceConfig={"maxTokens": 800, "temperature": 0},
        )
        return "".join(part.get("text", "") for part in resp["output"]["message"]["content"])

    def stream(self, prompt: str) -> Iterator[str]:
        resp = self._client.converse_stream(
            modelId=self.model_id,
            system=[{"text": _SYSTEM}],
            messages=[{"role": "user", "content": [{"text": prompt}]}],
            inferenceConfig={"maxTokens": 800, "temperature": 0},
        )
        for event in resp["stream"]:
            delta = event.get("contentBlockDelta", {}).get("delta", {})
            if "text" in delta:
                yield delta["text"]
