"""Patch 4: every failure lands in a known state that an operator can see and stop."""

import pytest

from sec310_sample.errors import InvalidTransition, Overloaded, PermanentError, TransientError
from sec310_sample.identity import RequestIdentity
from sec310_sample.orchestration import (
    CaseEvent,
    DurableJobStore,
    InMemoryStopStore,
    InvestigationCoordinator,
    JobRecord,
    JobState,
)
from tests.conftest import load_fixture

ALICE = RequestIdentity(
    "tenant-a", "alice", frozenset({"acct-a", "acct-b"}), frozenset({"analyst"})
)
CASE_7 = CaseEvent("case-7", "tenant-a", ("acct-a", "acct-b"))


class FakeClock:
    def __init__(self) -> None:
        self.now = 1_000.0

    def __call__(self) -> float:
        return self.now

    def advance(self, seconds: float) -> None:
        self.now += seconds


def scripted_worker(script: dict[str, list[str]], clock: FakeClock | None = None):
    """Per-account outcomes: 'ok', 'transient', 'permanent', 'slow'."""
    calls: dict[str, int] = {}

    def worker(job: JobRecord, deadline: float) -> dict:
        n = calls.get(job.account_id, 0)
        calls[job.account_id] = n + 1
        step = script[job.account_id][min(n, len(script[job.account_id]) - 1)]
        if step == "transient":
            raise TransientError("downstream_throttled")
        if step == "permanent":
            raise PermanentError("account_not_entitled")
        if step == "slow" and clock is not None:
            clock.advance(999)
        return {
            "account_id": job.account_id,
            "finding_count": 2 if job.account_id == "acct-a" else 1,
        }

    return worker


@pytest.fixture
def clock():
    return FakeClock()


@pytest.fixture
def stop():
    return InMemoryStopStore()


@pytest.fixture
def coordinator(stop, clock):
    return InvestigationCoordinator(
        stop, clock=clock, max_concurrency=2, retry_budget=2, job_timeout_s=30, stale_after_s=60
    )


def test_case_fans_out_per_account_and_recovers_from_a_transient_failure(coordinator):
    fixture = load_fixture("case-7")
    admitted = coordinator.admit(ALICE, CASE_7)
    assert admitted.status == "accepted" and admitted.jobs == ("case-7/acct-a", "case-7/acct-b")

    outcomes = coordinator.drain(scripted_worker(fixture["script"]))

    assert [o.status for o in outcomes] == ["completed", "retry_scheduled", "completed"]
    summary = coordinator.aggregate("case-7")
    assert summary["state"] == "COMPLETED"
    assert summary["accounts"]["acct-b"]["attempts"] == 2
    assert summary["findings"] == 3


def test_retry_budget_is_finite_and_ends_in_a_dead_letter(coordinator):
    coordinator.admit(ALICE, CASE_7)

    outcomes = coordinator.drain(
        scripted_worker({"acct-a": ["ok"], "acct-b": ["transient", "transient", "transient"]})
    )

    assert outcomes[-1].status == "failed" and "retry_budget_exhausted" in outcomes[-1].reason
    assert [j.job_id for j in coordinator.dead_letters()] == ["case-7/acct-b"]
    assert (
        coordinator.aggregate("case-7")["state"] == "COMPLETED"
    )  # partial success is visible, not hidden


def test_operator_stop_is_checked_before_admission_and_before_every_job(coordinator, stop):
    stop.disable("tenant-a", "case-7")
    assert coordinator.admit(ALICE, CASE_7).reason == "operator_stop"

    stop.enable("tenant-a", "case-7")
    coordinator.admit(ALICE, CASE_7)
    coordinator.run_next(scripted_worker({"acct-a": ["ok"], "acct-b": ["ok"]}))  # acct-a finishes
    stop.disable("tenant-a")  # operator pulls the cord mid-case

    outcome = coordinator.run_next(scripted_worker({"acct-a": ["ok"], "acct-b": ["ok"]}))

    assert outcome.status == "stopped"
    assert coordinator.aggregate("case-7")["state"] == "STOPPED"


def test_stop_control_outage_fails_closed(coordinator, stop):
    stop.unavailable = True
    assert coordinator.admit(ALICE, CASE_7).reason == "stop_control_unavailable"

    stop.unavailable = False
    coordinator.admit(ALICE, CASE_7)
    stop.unavailable = True
    outcome = coordinator.run_next(scripted_worker({"acct-a": ["ok"], "acct-b": ["ok"]}))

    assert outcome.status == "rejected" and outcome.reason == "stop_control_unavailable"
    assert coordinator.store.get("case-7/acct-a").state is JobState.WAITING  # nothing started blind


def test_concurrency_is_bounded_with_an_explicit_overload_signal(stop, clock):
    coordinator = InvestigationCoordinator(stop, clock=clock, max_concurrency=2)
    coordinator.admit(ALICE, CaseEvent("case-8", "tenant-a", ("acct-a", "acct-b")))
    coordinator.admit(ALICE, CaseEvent("case-9", "tenant-a", ("acct-a",)))
    coordinator.start_next()
    coordinator.start_next()

    with pytest.raises(Overloaded) as exc:
        coordinator.start_next()
    assert exc.value.retry_after_s == 5


def test_timeout_becomes_a_retryable_state_not_a_hung_worker(coordinator, clock):
    coordinator.admit(ALICE, CaseEvent("case-10", "tenant-a", ("acct-a",)))

    outcome = coordinator.run_next(scripted_worker({"acct-a": ["slow", "ok"]}, clock))

    assert outcome.status == "retry_scheduled" and outcome.reason == "timeout"
    assert coordinator.run_next(scripted_worker({"acct-a": ["ok"]})).status == "completed"


def test_stale_running_jobs_are_reclaimed(coordinator, clock):
    coordinator.admit(ALICE, CaseEvent("case-11", "tenant-a", ("acct-a",)))
    coordinator.start_next()  # worker dies here
    clock.advance(61)

    assert coordinator.reclaim_stale() == ["case-11/acct-a"]
    job = coordinator.store.get("case-11/acct-a")
    assert job.state is JobState.WAITING and job.attempt == 2


def test_duplicate_admission_does_not_duplicate_work(coordinator):
    first = coordinator.admit(ALICE, CASE_7)
    second = coordinator.admit(ALICE, CASE_7)

    assert first.jobs == ("case-7/acct-a", "case-7/acct-b")
    assert second.jobs == () and set(second.skipped) == {
        ("acct-a", "duplicate"),
        ("acct-b", "duplicate"),
    }
    assert len(coordinator.queue) == 2


def test_unreachable_accounts_are_skipped_not_investigated(coordinator):
    carol = RequestIdentity("tenant-a", "carol", frozenset({"acct-a"}))

    admitted = coordinator.admit(carol, CASE_7)

    assert admitted.jobs == ("case-7/acct-a",)
    assert admitted.skipped == (("acct-b", "target_not_authorized"),)


def test_conditional_transitions_reject_stale_writes():
    store = DurableJobStore()
    store.put_if_absent(JobRecord("j", "c", "tenant-a", "acct-a"))
    store.transition("j", JobState.WAITING, JobState.RUNNING, 1.0)

    with pytest.raises(InvalidTransition):
        store.transition(
            "j", JobState.WAITING, JobState.RUNNING, 2.0
        )  # someone else already started it

    store.transition(
        "j", JobState.RUNNING, JobState.WAITING, 3.0, attempt=2
    )  # legal: stale reclaim
    with pytest.raises(InvalidTransition):
        store.transition("j", JobState.WAITING, JobState.COMPLETED, 4.0)  # not a legal edge


def test_policy_table_pins_the_behaviour_it_documents():
    from sec310_sample.failure_policy import POLICIES, FailurePolicy, policy_for

    assert (
        policy_for("operator_stop") is FailurePolicy.FAIL_CLOSED
    )  # admit()/start_next() reject when unavailable
    assert (
        policy_for("downstream_overload") is FailurePolicy.RETRY_BOUNDED
    )  # start_next() raises Overloaded
    assert (
        policy_for("guardrail") is FailurePolicy.DEGRADED_READ_ONLY
    )  # assistant keeps reads, drops writes
    assert (
        policy_for("tracing") is FailurePolicy.DEGRADED_READ_ONLY
    )  # GuardedSink drops events, not requests
    assert policy_for("something-nobody-classified") is FailurePolicy.FAIL_CLOSED
    assert "something-nobody-classified" not in POLICIES


def test_complete_refuses_jobs_that_were_never_started(coordinator):
    coordinator.admit(ALICE, CaseEvent("case-12", "tenant-a", ("acct-a",)))
    ran = []

    with pytest.raises(InvalidTransition, match="requires RUNNING"):
        coordinator.complete("case-12/acct-a", lambda job, deadline: ran.append(job.job_id) or {})

    assert ran == []  # the worker never executed against a job in the wrong state


class TestBedrockGuardrailDecisionMapping:
    """Only an explicit action is a verdict; anything else is UNAVAILABLE, never a clean pass."""

    @staticmethod
    def _assess(response):
        from sec310_sample.guardrails import BedrockGuardrail

        class Client:
            def apply_guardrail(self, **kw):
                return response

        return BedrockGuardrail(guardrail_id="g", version="DRAFT", client=Client()).assess(
            "hi", "INPUT"
        )

    def test_explicit_none_is_clean(self):
        d = self._assess({"action": "NONE", "assessments": []})
        assert not d.intervened and not d.unavailable

    def test_intervened_carries_reasons(self):
        d = self._assess(
            {
                "action": "GUARDRAIL_INTERVENED",
                "assessments": [{"contentPolicy": {"filters": [{"type": "PROMPT_ATTACK"}]}}],
            }
        )
        assert d.intervened and d.reasons == ("contentPolicy:PROMPT_ATTACK",)

    @pytest.mark.parametrize(
        "response", [{}, {"assessments": []}, {"action": "BLOCKED"}, {"action": None}]
    )
    def test_missing_or_unknown_action_is_unavailable(self, response):
        d = self._assess(response)
        assert d.unavailable and not d.intervened
        assert d.reasons[0].startswith("unexpected_action:")
