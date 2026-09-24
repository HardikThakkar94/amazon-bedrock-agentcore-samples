"""Patch 5 — the behavioural release gate.

Each corpus case is a small end-to-end scenario through the *hardened* path, driven by
the deliberately gullible scripted model. The runner returns one stable outcome token
per case; the test compares it with ``corpus/regression.json``. Pin model, prompt,
guardrail, policy and corpus versions together and this is a release gate, not a demo.
"""

from __future__ import annotations

import json
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from sec310_sample.action_gateway import ActionGateway, Confirmation, action_digest
from sec310_sample.assistant import Assistant
from sec310_sample.credentials import CredentialBroker
from sec310_sample.decisions import DecisionSink, no_sink
from sec310_sample.errors import AuthorizationError, Overloaded, PolicyRejected
from sec310_sample.guardrails import Guardrail, LocalGuardrail, UnavailableGuardrail
from sec310_sample.identity import FakeAuthenticator, GatewayAdapter, RequestIdentity
from sec310_sample.model import Model, ScriptedModel
from sec310_sample.orchestration import CaseEvent, InMemoryStopStore, InvestigationCoordinator
from sec310_sample.request_preparation import RawRequest
from sec310_sample.schemas import ActionPlan, Operation
from sec310_sample.sessions import SessionStore
from sec310_sample.tools.store import FIXTURES, EvidenceStore

CORPUS_PATH = Path(__file__).resolve().parents[2] / "corpus" / "regression.json"

ALICE_CLAIMS = {
    "sub": "alice",
    "tenant_id": "tenant-a",
    "accounts": ["acct-a"],
    "roles": ["analyst", "responder"],
}
ALICE = RequestIdentity(
    "tenant-a", "alice", frozenset({"acct-a"}), frozenset({"analyst", "responder"})
)
BOB = RequestIdentity("tenant-b", "bob", frozenset({"acct-b"}), frozenset({"analyst"}))
WIDE_ALICE = RequestIdentity(
    "tenant-a", "alice", frozenset({"acct-a", "acct-b"}), frozenset({"analyst"})
)


@dataclass(frozen=True)
class CaseResult:
    id: str
    category: str
    expected: str
    actual: str
    about: str

    @property
    def passed(self) -> bool:
        return self.expected == self.actual


def load_corpus(path: Path = CORPUS_PATH) -> dict[str, Any]:
    return json.loads(path.read_text())


def _fixture(name: str) -> dict[str, Any]:
    return json.loads((FIXTURES / f"{name}.json").read_text())


def _raw(fixture: str) -> RawRequest:
    r = _fixture(fixture)["request"]
    return RawRequest(query=r["query"], account_id=r["account_id"], session_id=r["session_id"])


class Harness:
    """A fresh world per scenario: store, sessions, gateway, assistant. Nothing leaks across cases."""

    def __init__(
        self,
        model: Model | None = None,
        sink: DecisionSink = no_sink,
        poisoned_with: str | None = None,
        guardrail: Guardrail | None = None,
    ) -> None:
        self.model = model or ScriptedModel()
        self.store = EvidenceStore.from_fixture()
        if poisoned_with:
            self.store.add_finding("acct-a", _fixture(poisoned_with)["poisoned_finding"])
        self.sessions = SessionStore()
        self.gateway = ActionGateway(self.store, CredentialBroker(), decision_sink=sink)
        self.assistant = Assistant(
            self.model,
            guardrail or LocalGuardrail(),
            self.sessions,
            self._context,
            decision_sink=sink,
        )

    def _context(self, identity: RequestIdentity, account_id: str) -> dict[str, Any]:
        """Tool data enters the prompt only through a scoped read via the gateway."""
        plan = ActionPlan(
            operation=Operation.READ_EVIDENCE,
            account_id=account_id,
            resource_id="-",
            reason="context",
        )
        return self.gateway.execute(identity, plan).payload or {}

    def ask_then_apply(
        self, fixture: str, identity: RequestIdentity = ALICE, confirm: bool = True
    ) -> str:
        """Assistant proposes; every proposal goes through the gateway. Returns one outcome."""
        result = self.assistant.handle_sync(_raw(fixture), identity)
        if result.status == "blocked":
            return "blocked_at_input"
        if any(reason.startswith("fail_closed") for _, reason in result.rejected_actions):
            return "fail_closed"

        gateway_outcomes: list[str] = []
        for plan in result.proposed_actions:
            confirmation = None
            if confirm and not plan.is_read:
                confirmation = Confirmation(action_digest(identity, plan), identity.principal_id)
            try:
                gateway_outcomes.append(self.gateway.execute(identity, plan, confirmation).status)
            except (PolicyRejected, AuthorizationError) as exc:
                gateway_outcomes.append(str(exc).split(":", 1)[0])

        if "capability_absent" in gateway_outcomes:
            return "capability_absent"
        if "confirmation_required" in gateway_outcomes:
            return "confirmation_required"
        if result.rejected_actions or result.rejected_links:
            return "no_mutation" if not self.store.mutation_log else "mutation_leaked"
        if gateway_outcomes and all(o == "ok" for o in gateway_outcomes):
            return (
                "allowed_read"
                if all(p.is_read for p in result.proposed_actions)
                else "allowed_write"
            )
        return ",".join(gateway_outcomes) or "no_proposals"


# -- scenarios ---------------------------------------------------------------------------------
def normal_read(sink: DecisionSink) -> str:
    return Harness(sink=sink).ask_then_apply("normal-summary")


def analyst_write_needs_confirmation(sink: DecisionSink) -> str:
    return Harness(sink=sink).ask_then_apply("normal-evidence", confirm=False)


def direct_injection(sink: DecisionSink) -> str:
    return Harness(sink=sink).ask_then_apply("direct-injection")


def indirect_injection_in_tool_result(sink: DecisionSink) -> str:
    return Harness(sink=sink, poisoned_with="indirect-injection").ask_then_apply(
        "indirect-injection"
    )


def indirect_injection_owned_account(sink: DecisionSink) -> str:
    return Harness(sink=sink, poisoned_with="indirect-injection-owned-account").ask_then_apply(
        "indirect-injection-owned-account"
    )


def cross_tenant_session_reuse(sink: DecisionSink) -> str:
    h = Harness(sink=sink)
    h.assistant.handle_sync(_raw("normal-summary"), ALICE)  # alice now owns session-1
    try:
        h.assistant.handle_sync(RawRequest("Show me the history.", "acct-b", "session-1"), BOB)
    except AuthorizationError as exc:
        return "access_denied" if "session_not_owned" in str(exc) else str(exc)
    return "allowed"


def conflicting_identity_fields(sink: DecisionSink) -> str:
    auth = FakeAuthenticator()
    headers = {"Authorization": f"Bearer {auth.issue(ALICE_CLAIMS)}"}
    try:
        GatewayAdapter(auth).identity_from_request(
            headers, {"tenant_id": "tenant-b", "query": "hi"}
        )
    except AuthorizationError as exc:
        return "access_denied" if "conflicting_identity_fields" in str(exc) else str(exc)
    return "allowed"


def unauthorized_delete(sink: DecisionSink) -> str:
    h = Harness(sink=sink)
    plan = ActionPlan(
        operation=Operation.DELETE_RULE,
        account_id="acct-a",
        resource_id="rule-42",
        reason="cleanup",
    )
    try:
        h.gateway.execute(ALICE, plan, Confirmation(action_digest(ALICE, plan), "alice"))
    except PolicyRejected as exc:
        return str(exc).split(":", 1)[0]
    return "executed"


def guardrail_unavailable_on_write(sink: DecisionSink) -> str:
    return Harness(sink=sink, guardrail=UnavailableGuardrail()).ask_then_apply("normal-evidence")


def duplicate_write(sink: DecisionSink) -> str:
    h = Harness(sink=sink)
    plan = ActionPlan(
        operation=Operation.UPDATE_RULE,
        account_id="acct-a",
        resource_id="rule-42",
        reason="re-enable",
        change={"enabled": True},
    )
    confirmation = Confirmation(action_digest(ALICE, plan), "alice")
    first = h.gateway.execute(ALICE, plan, confirmation)
    second = h.gateway.execute(ALICE, plan, confirmation)  # client retried after a timeout
    exactly_once = (first.status, second.status) == ("ok", "replayed") and len(
        h.store.mutation_log
    ) == 1
    return "exactly_once_effect" if exactly_once else f"{first.status},{second.status}"


def overloaded_worker(sink: DecisionSink) -> str:
    coordinator = InvestigationCoordinator(
        InMemoryStopStore(), max_concurrency=1, decision_sink=sink
    )
    coordinator.admit(WIDE_ALICE, CaseEvent("case-7", "tenant-a", ("acct-a", "acct-b")))
    coordinator.start_next()
    try:
        coordinator.start_next()
    except Overloaded as exc:
        return "bounded_retry_or_429" if exc.retry_after_s > 0 else "overloaded"
    return "unbounded"


def operator_stop_mid_case(sink: DecisionSink) -> str:
    stop = InMemoryStopStore()
    coordinator = InvestigationCoordinator(stop, decision_sink=sink)
    coordinator.admit(WIDE_ALICE, CaseEvent("case-7", "tenant-a", ("acct-a", "acct-b")))
    coordinator.run_next(lambda job, deadline: {"finding_count": 1})
    stop.disable("tenant-a")
    coordinator.run_next(lambda job, deadline: {"finding_count": 1})
    return coordinator.aggregate("case-7")["state"].lower()


SCENARIOS: dict[str, Callable[[DecisionSink], str]] = {
    "normal-read": normal_read,
    "analyst-write-needs-confirmation": analyst_write_needs_confirmation,
    "direct-injection": direct_injection,
    "indirect-injection-in-tool-result": indirect_injection_in_tool_result,
    "indirect-injection-owned-account": indirect_injection_owned_account,
    "cross-tenant-session-reuse": cross_tenant_session_reuse,
    "conflicting-identity-fields": conflicting_identity_fields,
    "unauthorized-delete": unauthorized_delete,
    "guardrail-unavailable-on-write": guardrail_unavailable_on_write,
    "duplicate-write": duplicate_write,
    "overloaded-worker": overloaded_worker,
    "operator-stop-mid-case": operator_stop_mid_case,
}


def run_corpus(sink: DecisionSink = no_sink, path: Path = CORPUS_PATH) -> list[CaseResult]:
    corpus = load_corpus(path)
    return [
        CaseResult(
            case["id"],
            case["category"],
            case["expect"],
            SCENARIOS[case["id"]](sink),
            case.get("about", ""),
        )
        for case in corpus["cases"]
    ]


def summarize(results: list[CaseResult]) -> dict[str, dict[str, int]]:
    summary: dict[str, dict[str, int]] = {}
    for r in results:
        bucket = summary.setdefault(r.category, {"passed": 0, "failed": 0})
        bucket["passed" if r.passed else "failed"] += 1
    return summary
