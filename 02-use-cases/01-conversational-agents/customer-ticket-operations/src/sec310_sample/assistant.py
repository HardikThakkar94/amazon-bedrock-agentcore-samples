"""Patch 2 — the assistant, with one pipeline shared by sync and streaming.

Flow: own the session → check the target is reachable → fetch context through a tool
→ prepare once → guardrail(INPUT) → model → typed parse → validate → guardrail(OUTPUT)
→ apply the failure policy → record. The model's proposals come back as *proposals*.
Nothing here executes anything.
"""

from __future__ import annotations

import time
from collections.abc import Callable, Iterator
from dataclasses import dataclass, field
from typing import Any

from sec310_sample.decisions import Decision, DecisionSink, GuardedSink, no_sink
from sec310_sample.errors import AuthorizationError, OutputValidationError
from sec310_sample.guardrails import Guardrail, GuardrailDecision
from sec310_sample.identity import RequestIdentity
from sec310_sample.model import Model
from sec310_sample.output_validation import ValidatedResponse, validate_response
from sec310_sample.request_preparation import (
    PreparedRequest,
    RawRequest,
    build_prompt,
    prepare_request,
)
from sec310_sample.schemas import ActionPlan, parse_model_output
from sec310_sample.sessions import SessionStore

ContextProvider = Callable[[RequestIdentity, str], Any]

BLOCKED_MESSAGE = "This request was blocked by an input control."
DEGRADED_NOTE = "Safety checks were partially unavailable; only read-only proposals were kept."


@dataclass(frozen=True)
class AssistantResult:
    status: str  # ok | blocked | degraded
    answer: str
    proposed_actions: tuple[ActionPlan, ...] = ()
    links: tuple[str, ...] = ()
    rejected_links: tuple[tuple[str, str], ...] = ()
    rejected_actions: tuple[tuple[str, str], ...] = ()  # (operation@account, reason)
    guardrail_input: str = "NONE"
    guardrail_output: str = "NONE"
    degraded: bool = False
    notes: tuple[str, ...] = field(default_factory=tuple)

    @property
    def policy_outcome(self) -> tuple[Any, ...]:
        """Everything a client could act on. Sync and stream must agree on this exactly."""
        return (
            self.status,
            tuple((p.operation.value, p.account_id, p.resource_id) for p in self.proposed_actions),
            self.links,
            self.rejected_links,
            self.rejected_actions,
            self.degraded,
        )


class Assistant:
    def __init__(
        self,
        model: Model,
        guardrail: Guardrail,
        sessions: SessionStore,
        context_provider: ContextProvider,
        decision_sink: DecisionSink = no_sink,
    ) -> None:
        self._model = model
        self._guardrail = guardrail
        self._sessions = sessions
        self._context = context_provider
        self._emit = GuardedSink(decision_sink)

    # -- adapters ---------------------------------------------------------------
    def handle_sync(self, raw: RawRequest, identity: RequestIdentity) -> AssistantResult:
        prepared, input_decision = self._prepare(raw, identity)
        if input_decision.intervened:
            return self._blocked(prepared, input_decision)
        raw_output = self._model.complete(build_prompt(prepared))
        return self._finalize(prepared, raw_output, input_decision)

    def handle_stream(
        self, raw: RawRequest, identity: RequestIdentity
    ) -> Iterator[str | AssistantResult]:
        """Yields text chunks *after* validation, then the final result.

        Streaming is a separate product path with the same controls. The client never
        sees a token that has not passed the same gate as the synchronous answer.
        """
        prepared, input_decision = self._prepare(raw, identity)
        if input_decision.intervened:
            result = self._blocked(prepared, input_decision)
            yield result.answer
            yield result
            return
        buffered = "".join(self._model.stream(build_prompt(prepared)))  # gate, don't leak
        result = self._finalize(prepared, buffered, input_decision)
        step = max(1, len(result.answer) // 4)
        for i in range(0, len(result.answer), step):
            yield result.answer[i : i + step]
        yield result

    # -- shared pipeline -----------------------------------------------------------
    def _prepare(
        self, raw: RawRequest, identity: RequestIdentity
    ) -> tuple[PreparedRequest, GuardrailDecision]:
        t0 = time.perf_counter()
        self._sessions.get_or_create(identity, raw.session_id)  # raises session_not_owned
        if not identity.can_reach(raw.account_id):
            self._decide(
                "identity",
                "target_scope",
                "denied",
                identity,
                raw.session_id,
                target_class="account",
                t0=t0,
            )
            raise AuthorizationError("target_not_authorized")
        context = self._context(identity, raw.account_id)
        prepared = prepare_request(raw, identity, context)
        decision = self._guardrail.assess(prepared.query, "INPUT")
        self._decide(
            "input",
            "guardrail",
            decision.action.value.lower(),
            identity,
            raw.session_id,
            t0=t0,
            detail=",".join(decision.reasons),
        )
        return prepared, decision

    def _finalize(
        self, prepared: PreparedRequest, raw_output: str, input_decision: GuardrailDecision
    ) -> AssistantResult:
        t0 = time.perf_counter()
        identity = prepared.identity
        try:
            response = parse_model_output(raw_output)
        except OutputValidationError as exc:
            self._decide(
                "output",
                "schema",
                "rejected",
                identity,
                prepared.session_id,
                t0=t0,
                detail=str(exc),
            )
            return AssistantResult(
                status="blocked", answer="The model response failed validation.", notes=(str(exc),)
            )

        validated: ValidatedResponse = validate_response(response, identity)
        for link, reason in validated.rejected_links:
            self._decide(
                "output",
                "link_validator",
                reason,
                identity,
                prepared.session_id,
                t0=t0,
                detail=link,
            )
        for plan, reason in validated.rejected_actions:
            self._decide(
                "output",
                "target_scope",
                reason,
                identity,
                prepared.session_id,
                tool_name=plan.operation.value,
                target_class=plan.target_class,
                t0=t0,
            )

        output_decision = (
            input_decision
            if input_decision.unavailable
            else self._guardrail.assess(validated.answer, "OUTPUT")
        )
        if output_decision.intervened:
            self._decide("output", "guardrail", "intervened", identity, prepared.session_id, t0=t0)
            return AssistantResult(
                status="blocked",
                answer="The response was withheld by an output control.",
                guardrail_input=input_decision.action.value,
                guardrail_output=output_decision.action.value,
            )

        actions = list(validated.proposed_actions)
        rejected = [
            (f"{p.operation.value}@{p.account_id}", r) for p, r in validated.rejected_actions
        ]
        degraded = False
        notes: list[str] = []
        if input_decision.unavailable or output_decision.unavailable:
            # Failure policy for the guardrail dependency: reads may continue, writes fail closed.
            kept = [p for p in actions if p.is_read]
            for p in actions:
                if not p.is_read:
                    rejected.append(
                        (f"{p.operation.value}@{p.account_id}", "fail_closed:guardrail_unavailable")
                    )
                    self._decide(
                        "output",
                        "failure_policy",
                        "fail_closed",
                        identity,
                        prepared.session_id,
                        tool_name=p.operation.value,
                        target_class=p.target_class,
                        t0=t0,
                    )
            actions = kept
            degraded = True
            notes.append(DEGRADED_NOTE)

        self._sessions.append_turn(identity, prepared.session_id, prepared.query)
        self._decide(
            "model",
            "assistant",
            "degraded" if degraded else "ok",
            identity,
            prepared.session_id,
            t0=t0,
        )
        return AssistantResult(
            status="degraded" if degraded else "ok",
            answer=validated.answer,
            proposed_actions=tuple(actions),
            links=validated.links,
            rejected_links=validated.rejected_links,
            rejected_actions=tuple(rejected),
            guardrail_input=input_decision.action.value,
            guardrail_output=output_decision.action.value,
            degraded=degraded,
            notes=tuple(notes),
        )

    def _blocked(self, prepared: PreparedRequest, decision: GuardrailDecision) -> AssistantResult:
        return AssistantResult(
            status="blocked",
            answer=BLOCKED_MESSAGE,
            guardrail_input=decision.action.value,
            notes=decision.reasons,
        )

    def _decide(
        self,
        stage: str,
        control: str,
        outcome: str,
        identity: RequestIdentity,
        session_id: str,
        *,
        tool_name: str | None = None,
        target_class: str | None = None,
        t0: float,
        detail: str = "",
    ) -> None:
        self._emit(
            Decision(
                stage,
                control,
                outcome,
                identity,
                session_id,
                tool_name,
                target_class,
                int((time.perf_counter() - t0) * 1000),
                detail,
            )
        )
