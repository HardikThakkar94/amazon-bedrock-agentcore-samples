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


def _response_tool() -> dict:
    """The output contract, offered to the model as the one tool it must call.

    The schema is the same pydantic model the sample validates against, so the typed shape is
    requested at the API boundary and still checked on the way back in. Observed 2026-10-08:
    without this, a capable model wraps the JSON in a Markdown fence, which the strict parser
    rightly rejects.
    """
    from sec310_sample.schemas import AssistantResponse  # local: keep module import light

    schema = AssistantResponse.model_json_schema()
    # Pydantic leaves fields with defaults out of `required`; Sonnet 5 then omits an empty
    # proposed_actions/links (observed 2026-10-09) while Haiku 4.5 always sent them. Ask for the
    # whole shape every time so every consumer sees the same keys.
    schema["required"] = sorted(schema["properties"])
    return {
        "toolSpec": {
            "name": "respond",
            "description": "Return the assistant response in the required shape.",
            "inputSchema": {"json": schema},
        }
    }


_FENCE_RE = re.compile(r"```(?:json)?\s*(\{.*\})\s*```", re.DOTALL)
_FORCED_TOOL_CHOICE = {"tool": {"name": "respond"}}
_AUTO_TOOL_CHOICE = {"auto": {}}


def _validation_message(exc: BaseException) -> str:
    response = getattr(exc, "response", None)
    if not isinstance(response, dict):
        return ""
    error = response.get("Error", {})
    if error.get("Code") != "ValidationException":
        return ""
    return str(error.get("Message", ""))


def _rejects_forced_tool_choice(exc: BaseException) -> bool:
    # Opus 5.5: 'tool_choice: type "tool" and "any" are not supported for this model.'
    # Palmyra X4, Llama 4 Maverick: "This model doesn't support the toolConfig.toolChoice.tool field."
    message = _validation_message(exc)
    return "tool_choice" in message or "toolChoice.tool" in message


def _rejects_tool_use(exc: BaseException) -> bool:
    # Llama 3 8B, Mixtral: "This model doesn't support tool use."
    return "doesn't support tool use" in _validation_message(exc)


def _rejects_system_messages(exc: BaseException) -> bool:
    # Mixtral 8x7B, Mistral 7B: "This model doesn't support system messages."
    return "doesn't support system messages" in _validation_message(exc)


def _unfence(text: str) -> str:
    """Models that answer in text often wrap the JSON in a code fence. The fence is transport
    noise, not content: hand the parser the object inside it. Anything else goes through
    untouched, so a reply that is not JSON is still reported as malformed, not guessed at."""
    match = _FENCE_RE.search(text)
    return match.group(1) if match else text.strip()


class BedrockModel:
    """Opt-in live model via the Bedrock Converse API. Proposals only.

    Requires the ``aws`` extra and ``SEC310_MODEL_ID`` in the environment. Region and
    credentials come from the normal AWS SDK chain. Nothing here can mutate state. The response
    shape is requested with a forced tool call; ``complete``/``stream`` return its JSON input as
    text so the rest of the sample treats the live model exactly like the scripted one.

    Not every model on Bedrock accepts the same request (observed 2026-10-09): some reject a
    forced tool choice but call the offered tool under ``auto``; some reject tools altogether and
    answer in text; some reject system messages. The adapter starts strict and relaxes one
    capability at a time, only when the service names it in a ``ValidationException``, and keeps
    the relaxed shape for the rest of the instance. Any other error propagates.
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
        self._tool_choice: dict | None = _FORCED_TOOL_CHOICE  # None: no tools offered
        self._system_in_message = False
        self.run_id = os.environ.get("SEC310_RUN_ID")

    def _request(self, prompt: str) -> dict:
        request = {
            "modelId": self.model_id,
            "messages": [{"role": "user", "content": [{"text": prompt}]}],
            # maxTokens only: some models reject sampling parameters such as temperature. 800 was
            # too small for Sonnet 5 / Opus 5 (observed 2026-10-09: the tool input came back
            # truncated to {} with stopReason max_tokens); 2000 leaves room for a long answer.
            "inferenceConfig": {"maxTokens": 2000},
        }
        if self._system_in_message:
            request["messages"][0]["content"][0]["text"] = f"{_SYSTEM}\n\n{prompt}"
        else:
            request["system"] = [{"text": _SYSTEM}]
        if self._tool_choice is not None:
            request["toolConfig"] = {"tools": [_response_tool()], "toolChoice": self._tool_choice}
        if self.run_id:
            request["requestMetadata"] = {"sec310_run": self.run_id}
        return request

    def _relax(self, exc: BaseException) -> bool:
        """Drop exactly one capability the service just rejected. False: nothing to relax."""
        if _rejects_system_messages(exc) and not self._system_in_message:
            self._system_in_message = True
            return True
        if _rejects_tool_use(exc) and self._tool_choice is not None:
            self._tool_choice = None
            return True
        if _rejects_forced_tool_choice(exc) and self._tool_choice == _FORCED_TOOL_CHOICE:
            self._tool_choice = _AUTO_TOOL_CHOICE
            return True
        return False

    def _call(self, operation, prompt: str):
        while True:
            try:
                return operation(**self._request(prompt))
            except Exception as exc:  # noqa: BLE001 - only the named capability rejections are handled
                if not self._relax(exc):
                    raise

    def complete(self, prompt: str) -> str:
        resp = self._call(self._client.converse, prompt)
        if resp.get("stopReason") == "max_tokens":
            # A truncated tool input arrives as {} and would otherwise look like an empty but
            # well-formed reply. Hand back something the strict parser rejects, and that says why.
            return f"<model output truncated: stopReason=max_tokens, usage={resp.get('usage')}>"
        blocks = resp["output"]["message"]["content"]
        for block in blocks:
            if "toolUse" in block:
                return json.dumps(block["toolUse"]["input"])
        # No tool call: the model answered in text (no tool support, or it ignored the forced
        # choice, as Gemma does). Strip a code fence; anything else reaches the parser as is.
        return _unfence("".join(block.get("text", "") for block in blocks))

    def stream(self, prompt: str) -> Iterator[str]:
        resp = self._call(self._client.converse_stream, prompt)
        text_parts: list[str] = []
        saw_tool = False
        stop_reason = None
        for event in resp["stream"]:
            delta = event.get("contentBlockDelta", {}).get("delta", {})
            if "toolUse" in delta:
                saw_tool = True
                yield delta["toolUse"]["input"]
            elif "text" in delta:
                text_parts.append(delta["text"])
            if "messageStop" in event:
                stop_reason = event["messageStop"].get("stopReason")
        if stop_reason == "max_tokens":
            yield f"<model output truncated: stopReason={stop_reason}>"
        elif not saw_tool and text_parts:
            # Text answers are buffered so a code fence can be stripped; the consumer gates the
            # whole reply before showing any of it, so nothing is lost by yielding it at the end.
            yield _unfence("".join(text_parts))
