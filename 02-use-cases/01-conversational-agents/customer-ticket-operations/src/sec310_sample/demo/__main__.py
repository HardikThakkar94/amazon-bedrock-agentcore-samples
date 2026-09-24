from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Callable

from sec310_sample.action_gateway import ActionGateway, Confirmation, action_digest
from sec310_sample.assistant import Assistant
from sec310_sample.credentials import CredentialBroker
from sec310_sample.decisions import no_sink
from sec310_sample.errors import AuthorizationError, Overloaded, PolicyRejected, TransientError
from sec310_sample.evaluation import run_corpus, summarize
from sec310_sample.failure_policy import POLICIES
from sec310_sample.guardrails import Guardrail, LocalGuardrail, UnavailableGuardrail
from sec310_sample.identity import FakeAuthenticator, GatewayAdapter, RequestIdentity
from sec310_sample.model import Model, ScriptedModel
from sec310_sample.orchestration import (
    CaseEvent,
    InMemoryStopStore,
    InvestigationCoordinator,
    JobRecord,
)
from sec310_sample.request_preparation import RawRequest
from sec310_sample.schemas import ActionPlan, Operation
from sec310_sample.sessions import SessionStore
from sec310_sample.telemetry import Tracer, Versions
from sec310_sample.tools.store import FIXTURES, EvidenceStore
from sec310_sample.unsafe_agent import UnsafeAgent

# -- output helpers -------------------------------------------------------------------------
W = 78


def banner(title: str) -> None:
    print("\n" + "=" * W + f"\n  {title}\n" + "=" * W)


def step(text: str) -> None:
    print(f"\n→ {text}")


def ok(text: str) -> None:
    print(f"  ✔ {text}")


def denied(text: str) -> None:
    print(f"  ✖ {text}")


def note(text: str) -> None:
    print(f"  · {text}")


def show(label: str, obj: object) -> None:
    print(f"  {label}: {json.dumps(obj, indent=2, default=str).replace(chr(10), chr(10) + '  ')}")


def fixture(name: str) -> dict:
    return json.loads((FIXTURES / f"{name}.json").read_text())


def raw(name: str) -> RawRequest:
    r = fixture(name)["request"]
    return RawRequest(query=r["query"], account_id=r["account_id"], session_id=r["session_id"])


ALICE = RequestIdentity(
    "tenant-a", "alice", frozenset({"acct-a"}), frozenset({"analyst", "responder"})
)
BOB = RequestIdentity("tenant-b", "bob", frozenset({"acct-b"}), frozenset({"analyst"}))
WIDE_ALICE = RequestIdentity(
    "tenant-a", "alice", frozenset({"acct-a", "acct-b"}), frozenset({"analyst"})
)


class World:
    """One consistent set of components, rebuilt per stage."""

    def __init__(
        self, model: Model, guardrail: Guardrail, poisoned_with: str | None = None, sink=no_sink
    ) -> None:
        self.model = model
        self.store = EvidenceStore.from_fixture()
        if poisoned_with:
            self.store.add_finding("acct-a", fixture(poisoned_with)["poisoned_finding"])
        self.sessions = SessionStore()
        self.gateway = ActionGateway(self.store, CredentialBroker(), decision_sink=sink)
        self.assistant = Assistant(
            model, guardrail, self.sessions, self.context, decision_sink=sink
        )

    def context(self, identity: RequestIdentity, account_id: str) -> dict:
        plan = ActionPlan(
            operation=Operation.READ_EVIDENCE,
            account_id=account_id,
            resource_id="-",
            reason="context",
        )
        return self.gateway.execute(identity, plan).payload or {}


# -- stages -----------------------------------------------------------------------------------
def stage_unsafe(model: Model, guardrail: Guardrail) -> None:
    banner("v0  The dangerous success: a prototype that works, and follows anything it reads")
    store = EvidenceStore.from_fixture()
    store.add_finding("acct-a", fixture("indirect-injection")["poisoned_finding"])
    agent = UnsafeAgent(model, store)

    step("Alice (tenant-a) asks an honest question about her own account")
    show("request", fixture("indirect-injection")["request"])
    note("one finding in acct-a carries text an attacker controlled: a user-agent string")
    note(
        "acct-b belongs to tenant-b and currently has rule-77: "
        + json.dumps(store.rule("acct-b", "rule-77"))
    )

    result = agent.handle(fixture("indirect-injection")["request"])

    step("The agent answered correctly...")
    ok(result["answer"])
    step("...and also did this:")
    for action in result["executed"]:
        denied(
            f"{action['operation']} {action.get('account_id')} {action.get('resource_id', '')} → {action['status']}"
        )
    denied(f"links returned to the UI: {result['links']}")
    denied(f"acct-b rules now: {store.rules('acct-b')}   (tenant-b never saw this coming)")
    note(
        "Nothing was 'hacked'. Identity came from the body, tool data went in raw, and code obeyed the model."
    )


def stage_identity(model: Model, guardrail: Guardrail) -> None:
    banner("Patch 1  Identity before agency")
    auth = FakeAuthenticator()
    gateway = GatewayAdapter(auth)
    alice_token = auth.issue(
        {
            "sub": "alice",
            "tenant_id": "tenant-a",
            "accounts": ["acct-a"],
            "roles": ["analyst", "responder"],
        }
    )

    step("Identity is derived from the verified token, never from the body")
    identity, forwarded = gateway.forward(
        {"Authorization": f"Bearer {alice_token}", "X-Tenant-Id": "tenant-a", "X-Request-Id": "r1"},
        {"account_id": "acct-b", "query": "..."},
    )
    ok(f"headers forwarded downstream: {sorted(forwarded)}  (identity claims stripped)")
    ok(
        f"RequestIdentity(tenant_id={identity.tenant_id!r}, principal_id={identity.principal_id!r}, "
        f"allowed_accounts={sorted(identity.allowed_accounts)}, roles={sorted(identity.roles)})"
    )
    denied(
        "body asked for acct-b → identity.can_reach('acct-b') is "
        + str(identity.can_reach("acct-b"))
    )

    step("Caller-supplied identity that disagrees with the token is a signal, not a preference")
    try:
        gateway.identity_from_request(
            {"Authorization": f"Bearer {alice_token}", "X-Tenant-Id": "tenant-b"}, {}
        )
    except AuthorizationError as exc:
        denied(f"AuthorizationError: {exc}")

    step("Sessions are authorization domains: the owner is in the storage key")
    sessions = SessionStore()
    record = sessions.get_or_create(identity, "session-1")
    record.turns.append("alice: why was rule-42 disabled?")
    ok(f"stored under partition {record.partition}")
    try:
        sessions.get(BOB, "session-1")
    except AuthorizationError as exc:
        denied(f"bob (tenant-b) presents the same session id → {exc}")
    note("A random session id is a lookup hint. Ownership is checked on every read and write.")


def stage_untrusted(model: Model, guardrail: Guardrail) -> None:
    banner("Patch 2  Untrusted data stays data")

    step("Direct injection in the user query: stopped before inference")
    world = World(model, guardrail)
    result = world.assistant.handle_sync(raw("direct-injection"), ALICE)
    denied(
        f"status={result.status} guardrail_input={result.guardrail_input} reasons={list(result.notes)}"
    )

    step(
        "Indirect injection inside tool data: the keyword guardrail misses it, the model follows it..."
    )
    world = World(model, guardrail, poisoned_with="indirect-injection")
    result = world.assistant.handle_sync(raw("indirect-injection"), ALICE)
    note(f"guardrail_input={result.guardrail_input}  (nothing looked like an attack)")
    ok(f"answer: {result.answer}")
    step("...and deterministic validation still holds")
    for target, reason in result.rejected_actions:
        denied(f"proposal {target} rejected: {reason}")
    for link, reason in result.rejected_links:
        denied(f"link {link} rejected: {reason}")
    ok(f"links that reached the UI: {list(result.links)}")
    ok(f"mutations so far: {world.store.mutation_log}")

    step("Streaming is a separate product path with the same gate")
    events = list(
        World(model, guardrail, poisoned_with="indirect-injection").assistant.handle_stream(
            raw("indirect-injection"), ALICE
        )
    )
    stream_result = events[-1]
    ok(
        f"sync.policy_outcome == stream.policy_outcome → {result.policy_outcome == stream_result.policy_outcome}"
    )
    ok(f"'exfil' in streamed text → {'exfil' in ''.join(e for e in events if isinstance(e, str))}")

    step("Guardrail outage: reads continue in degraded mode, writes fail closed")
    world = World(model, UnavailableGuardrail())
    result = world.assistant.handle_sync(raw("normal-evidence"), ALICE)
    note(f"status={result.status}  kept={[p.operation.value for p in result.proposed_actions]}")
    ok(f"the read-only answer still came back: {result.answer[:60]}…")
    for target, reason in result.rejected_actions:
        denied(f"{target}: {reason}")
    note("A guardrail decision is a layer. It is never the permission to act.")


def stage_tools(model: Model, guardrail: Guardrail) -> None:
    banner("Patch 3  Tools encode blast radius")
    world = World(model, guardrail)
    gw = world.gateway

    step("The honest analyst asks to re-enable rule-42; the model proposes a typed update")
    result = world.assistant.handle_sync(raw("normal-evidence"), ALICE)
    plan = next(p for p in result.proposed_actions if p.operation is Operation.UPDATE_RULE)
    show("ActionPlan", plan.model_dump(mode="json"))

    step("Schema-valid is not authorized: the gateway asks for a human")
    pending = gw.execute(ALICE, plan)
    note(f"status={pending.status}  digest={pending.payload['action_digest'][:16]}…")

    step("A confirmation is bound to this identity and this exact plan")
    confirmation = Confirmation(action_digest(ALICE, plan), "alice")
    done = gw.execute(ALICE, plan, confirmation)
    ok(f"status={done.status}  rule-42 → {done.payload}")
    replay = gw.execute(ALICE, plan, confirmation)
    ok(
        f"client retried the same confirmed action → status={replay.status}, mutations={len(world.store.mutation_log)}"
    )
    ok(f"audit chain intact: {gw.audit.verify_chain()}  records={len(gw.audit)}")

    step(
        "Injected delete inside Alice's own scope: schema ok, target ok, confirmation ok... capability absent"
    )
    poisoned = World(model, guardrail, poisoned_with="indirect-injection-owned-account")
    result = poisoned.assistant.handle_sync(raw("indirect-injection-owned-account"), ALICE)
    for p in result.proposed_actions:
        try:
            poisoned.gateway.execute(ALICE, p, Confirmation(action_digest(ALICE, p), "alice"))
        except PolicyRejected as exc:
            denied(f"{p.operation.value} {p.account_id} {p.resource_id} → {exc}")
    ok(f"acct-a still has rule-42: {'rule-42' in poisoned.store.rules('acct-a')}")

    step("Read-only role, even with a confirmation, gets no write capability")
    carol = RequestIdentity("tenant-a", "carol", frozenset({"acct-a"}), frozenset({"analyst"}))
    fresh = World(model, guardrail)
    try:
        fresh.gateway.execute(carol, plan, Confirmation(action_digest(carol, plan), "carol"))
    except AuthorizationError as exc:
        denied(f"{exc}")
    note(
        "The model selects among capabilities. Deterministic code decides which capabilities exist."
    )


def stage_containment(model: Model, guardrail: Guardrail) -> None:
    banner("Patch 4  Design the stop path before autonomy")
    script = fixture("case-7")["script"]
    calls: dict[str, int] = {}

    def worker(job: JobRecord, deadline: float) -> dict:
        n = calls.get(job.account_id, 0)
        calls[job.account_id] = n + 1
        outcome = script[job.account_id][min(n, len(script[job.account_id]) - 1)]
        if outcome == "transient":
            raise TransientError("downstream_throttled")
        return {
            "account_id": job.account_id,
            "finding_count": 2 if job.account_id == "acct-a" else 1,
        }

    step("Failure direction is written down per dependency")
    for dep, policy in POLICIES.items():
        note(f"{dep:<22} {policy.value}")

    stop = InMemoryStopStore()
    coordinator = InvestigationCoordinator(stop, max_concurrency=2, retry_budget=2)

    step("case-7 fans out into one job per account, each with its own durable record")
    admitted = coordinator.admit(WIDE_ALICE, CaseEvent("case-7", "tenant-a", ("acct-a", "acct-b")))
    ok(f"admitted: {list(admitted.jobs)}")
    for outcome in coordinator.drain(worker):
        (ok if outcome.status == "completed" else note)(
            f"{outcome.job_id}: {outcome.status} {outcome.reason} (attempt {outcome.attempt})"
        )
    show("aggregate", coordinator.aggregate("case-7"))

    step("Operator pulls the cord between jobs")
    stop2 = InMemoryStopStore()
    c2 = InvestigationCoordinator(stop2)
    c2.admit(WIDE_ALICE, CaseEvent("case-8", "tenant-a", ("acct-a", "acct-b")))
    ok(f"{c2.run_next(worker).job_id}: completed")
    stop2.disable("tenant-a")
    outcome = c2.run_next(worker)
    denied(
        f"{outcome.job_id}: {outcome.status} ({outcome.reason})  case state = {c2.aggregate('case-8')['state']}"
    )

    step("Stop-control store unavailable: nothing privileged starts blind")
    stop2.enable("tenant-a")
    stop2.unavailable = True
    denied(f"admit → {c2.admit(WIDE_ALICE, CaseEvent('case-9', 'tenant-a', ('acct-a',))).reason}")

    step("Bounded concurrency gives an explicit overload signal, not a pile-up")
    c3 = InvestigationCoordinator(InMemoryStopStore(), max_concurrency=1)
    c3.admit(WIDE_ALICE, CaseEvent("case-10", "tenant-a", ("acct-a", "acct-b")))
    c3.start_next()
    try:
        c3.start_next()
    except Overloaded as exc:
        denied(f"Overloaded: retry_after_s={exc.retry_after_s}")
    note(
        "Not a runtime 'circuit breaker'. Bounded execution, retry budgets, a kill switch, and known terminal states."
    )


def stage_telemetry(model: Model, guardrail: Guardrail) -> None:
    banner("Patch 5  Observe decisions, and gate releases on behaviour")
    tracer = Tracer(Versions(model_version=model.version), key="demo-key")

    step("Run the versioned behavioural corpus through the hardened path")
    results = run_corpus(sink=tracer)
    for r in results:
        (ok if r.passed else denied)(
            f"{r.id:<36} {r.category:<9} expect={r.expected:<22} actual={r.actual}"
        )
    show("summary", summarize(results))

    step("Decision telemetry is hashed and versioned; free text never reaches the index")
    for event in tracer.export()[:4]:
        show("event", {k: v for k, v in event.items() if k != "latency_ms"})
    note(
        f"{len(tracer.events)} events recorded (latency_ms omitted from the excerpt; it varies by machine)"
    )
    tracer.assert_redacted(
        [
            "alice",
            "bob",
            "tenant-a",
            "tenant-b",
            "acct-a",
            "acct-b",
            "session-1",
            "rule-42",
            "rule-77",
            "exfil",
        ]
    )
    ok("no raw tenant/principal/account/session/rule identifiers in any indexed attribute")

    step("Top outcomes (the shape of a dashboard)")
    for (stage, control, outcome), count in tracer.outcomes().most_common(8):
        note(f"{count:>3}  {stage:<10} {control:<16} {outcome}")


STAGES: dict[str, Callable[[Model, Guardrail], None]] = {
    "unsafe": stage_unsafe,
    "identity": stage_identity,
    "untrusted": stage_untrusted,
    "tools": stage_tools,
    "containment": stage_containment,
    "telemetry": stage_telemetry,
}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m sec310_sample.demo", description=__doc__)
    parser.add_argument("stage", choices=[*STAGES, "all"])
    parser.add_argument(
        "--live",
        action="store_true",
        help="use Bedrock model/guardrail for proposals (needs SEC310_MODEL_ID, SEC310_GUARDRAIL_ID)",
    )
    args = parser.parse_args(argv)

    model: Model = ScriptedModel()
    guardrail: Guardrail = LocalGuardrail()
    if args.live:
        from sec310_sample.guardrails import BedrockGuardrail
        from sec310_sample.model import BedrockModel

        model, guardrail = BedrockModel(), BedrockGuardrail()
        print("live mode: proposals from Bedrock; the write path is still local and mock")

    for name in STAGES if args.stage == "all" else [args.stage]:
        STAGES[name](model, guardrail)
    print()
    return 0


if __name__ == "__main__":
    sys.exit(main())
