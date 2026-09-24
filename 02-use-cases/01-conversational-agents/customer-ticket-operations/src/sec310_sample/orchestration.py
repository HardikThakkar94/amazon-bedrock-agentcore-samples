"""Patch 4 — design the stop path before autonomy.

An asynchronous investigation fans one case out into one job per account. Each job
has its own identity scope, its own durable record, and its own terminal state. The
coordinator checks the operator stop control before admitting work and before
starting every job, bounds concurrency, bounds retries, and turns timeouts into a
known retryable state instead of a hung worker.

All of it is in-memory and driven by an injectable clock so the demo is deterministic.
The shapes (conditional transitions, FIFO with dedup, dead letters, heartbeats) map
directly onto a table + queue in any cloud.
"""

from __future__ import annotations

import time
from collections import deque
from collections.abc import Callable
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any, Protocol

from sec310_sample.decisions import Decision, DecisionSink, GuardedSink, no_sink
from sec310_sample.errors import InvalidTransition, Overloaded, PermanentError, TransientError
from sec310_sample.identity import RequestIdentity


# -- stop control ----------------------------------------------------------------------
@dataclass(frozen=True)
class StopDecision:
    disabled: bool = False
    unavailable: bool = False

    @property
    def allows_work(self) -> bool:
        return not (self.disabled or self.unavailable)


class StopControl(Protocol):
    def get(self, tenant_id: str, case_id: str) -> StopDecision: ...


class InMemoryStopStore:
    """Operator kill switch, scoped to a tenant or a single case.

    Can be made 'unavailable' to test the fail-closed path.
    """

    def __init__(self) -> None:
        self._disabled: set[tuple[str, str | None]] = set()
        self.unavailable = False

    def disable(self, tenant_id: str, case_id: str | None = None) -> None:
        self._disabled.add((tenant_id, case_id))

    def enable(self, tenant_id: str, case_id: str | None = None) -> None:
        self._disabled.discard((tenant_id, case_id))

    def get(self, tenant_id: str, case_id: str) -> StopDecision:
        if self.unavailable:
            return StopDecision(unavailable=True)
        return StopDecision(
            disabled=(tenant_id, None) in self._disabled or (tenant_id, case_id) in self._disabled
        )


# -- durable job records -------------------------------------------------------------------
class JobState(StrEnum):
    WAITING = "WAITING"
    RUNNING = "RUNNING"
    RETRYABLE_FAILURE = "RETRYABLE_FAILURE"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"
    STOPPED = "STOPPED"

    @property
    def terminal(self) -> bool:
        return self in (JobState.COMPLETED, JobState.FAILED, JobState.STOPPED)


TRANSITIONS: dict[JobState, frozenset[JobState]] = {
    JobState.WAITING: frozenset({JobState.RUNNING, JobState.STOPPED}),
    JobState.RUNNING: frozenset(
        {
            JobState.COMPLETED,
            JobState.RETRYABLE_FAILURE,
            JobState.FAILED,
            JobState.STOPPED,
            JobState.WAITING,
        }
    ),
    JobState.RETRYABLE_FAILURE: frozenset({JobState.WAITING, JobState.FAILED}),
    JobState.COMPLETED: frozenset(),
    JobState.FAILED: frozenset(),
    JobState.STOPPED: frozenset(),
}


@dataclass
class JobRecord:
    job_id: str
    case_id: str
    tenant_id: str
    account_id: str
    state: JobState = JobState.WAITING
    attempt: int = 1
    heartbeat_at: float = 0.0
    result: dict[str, Any] | None = None
    last_error: str | None = None
    history: list[tuple[str, float]] = field(default_factory=list)


class DurableJobStore:
    """Conditional writes only. A transition names the state it expects to leave."""

    def __init__(self) -> None:
        self._jobs: dict[str, JobRecord] = {}

    def put_if_absent(self, job: JobRecord) -> bool:
        if job.job_id in self._jobs:
            return False
        self._jobs[job.job_id] = job
        return True

    def transition(
        self, job_id: str, expected: JobState, new: JobState, at: float, **updates: Any
    ) -> JobRecord:
        job = self._jobs[job_id]
        if job.state is not expected:
            raise InvalidTransition(f"{job_id}: expected {expected.value}, found {job.state.value}")
        if new not in TRANSITIONS[expected]:
            raise InvalidTransition(f"{job_id}: {expected.value} -> {new.value} is not allowed")
        job.state = new
        job.history.append((new.value, at))
        for key, value in updates.items():
            setattr(job, key, value)
        return job

    def get(self, job_id: str) -> JobRecord:
        return self._jobs[job_id]

    def by_case(self, case_id: str) -> list[JobRecord]:
        return sorted(
            (j for j in self._jobs.values() if j.case_id == case_id), key=lambda j: j.job_id
        )

    def by_state(self, state: JobState) -> list[JobRecord]:
        return sorted((j for j in self._jobs.values() if j.state is state), key=lambda j: j.job_id)


class FifoQueue:
    def __init__(self) -> None:
        self._queue: deque[str] = deque()
        self._seen: set[str] = set()

    def enqueue(self, job_id: str) -> bool:
        if job_id in self._queue:
            return False
        self._queue.append(job_id)
        return True

    def pop(self) -> str | None:
        return self._queue.popleft() if self._queue else None

    def __len__(self) -> int:
        return len(self._queue)


# -- coordinator ------------------------------------------------------------------------------
@dataclass(frozen=True)
class CaseEvent:
    case_id: str
    tenant_id: str
    accounts: tuple[str, ...]


@dataclass(frozen=True)
class AdmissionResult:
    status: str  # accepted | rejected
    reason: str = ""
    jobs: tuple[str, ...] = ()
    skipped: tuple[tuple[str, str], ...] = ()


@dataclass(frozen=True)
class RunOutcome:
    job_id: str | None
    status: str  # completed | retry_scheduled | failed | stopped | rejected | idle
    reason: str = ""
    attempt: int = 0


Worker = Callable[[JobRecord, float], dict[str, Any]]  # (job, deadline) -> result


class InvestigationCoordinator:
    def __init__(
        self,
        stop_control: StopControl,
        store: DurableJobStore | None = None,
        queue: FifoQueue | None = None,
        clock: Callable[[], float] = time.monotonic,
        *,
        max_concurrency: int = 2,
        retry_budget: int = 2,
        job_timeout_s: float = 30.0,
        stale_after_s: float = 60.0,
        decision_sink: DecisionSink = no_sink,
    ) -> None:
        self._stop = stop_control
        self.store = store or DurableJobStore()
        self.queue = queue or FifoQueue()
        self._clock = clock
        self.max_concurrency = max_concurrency
        self.retry_budget = retry_budget
        self.job_timeout_s = job_timeout_s
        self.stale_after_s = stale_after_s
        self._emit = GuardedSink(decision_sink)
        self._in_flight: set[str] = set()

    # -- admission ---------------------------------------------------------------------
    def admit(self, identity: RequestIdentity, case: CaseEvent) -> AdmissionResult:
        if case.tenant_id != identity.tenant_id:
            return self._reject(identity, case, "tenant_mismatch")
        stop = self._stop.get(case.tenant_id, case.case_id)
        if stop.unavailable:
            return self._reject(identity, case, "stop_control_unavailable")
        if stop.disabled:
            return self._reject(identity, case, "operator_stop")

        jobs: list[str] = []
        skipped: list[tuple[str, str]] = []
        for account_id in case.accounts:
            if not identity.can_reach(account_id):
                skipped.append((account_id, "target_not_authorized"))
                continue
            job = JobRecord(
                job_id=f"{case.case_id}/{account_id}",
                case_id=case.case_id,
                tenant_id=case.tenant_id,
                account_id=account_id,
            )
            if not self.store.put_if_absent(job):
                skipped.append((account_id, "duplicate"))
                continue
            self.queue.enqueue(job.job_id)
            jobs.append(job.job_id)
        self._emit(
            Decision(
                "admission",
                "coordinator",
                "accepted",
                identity,
                None,
                None,
                "case",
                0,
                f"jobs={len(jobs)} skipped={len(skipped)}",
            )
        )
        return AdmissionResult("accepted", jobs=tuple(jobs), skipped=tuple(skipped))

    # -- execution -----------------------------------------------------------------------
    def start_next(self) -> RunOutcome:
        """Move one WAITING job to RUNNING, subject to stop control and the concurrency bound."""
        if len(self._in_flight) >= self.max_concurrency:
            raise Overloaded(retry_after_s=5)
        job_id = self.queue.pop()
        if job_id is None:
            return RunOutcome(None, "idle")
        job = self.store.get(job_id)
        stop = self._stop.get(job.tenant_id, job.case_id)
        if stop.unavailable:
            self.queue.enqueue(job_id)  # leave it WAITING; do not start privileged work blind
            return RunOutcome(job_id, "rejected", "stop_control_unavailable", job.attempt)
        if stop.disabled:
            self.store.transition(
                job_id,
                JobState.WAITING,
                JobState.STOPPED,
                self._clock(),
                last_error="operator_stop",
            )
            self._job_decision(job, "stopped")
            return RunOutcome(job_id, "stopped", "operator_stop", job.attempt)
        now = self._clock()
        self.store.transition(job_id, JobState.WAITING, JobState.RUNNING, now, heartbeat_at=now)
        self._in_flight.add(job_id)
        return RunOutcome(job_id, "running", attempt=job.attempt)

    def complete(self, job_id: str, worker: Worker) -> RunOutcome:
        """Run the worker for a RUNNING job and land it in exactly one known state."""
        job = self.store.get(job_id)
        if job.state is not JobState.RUNNING:
            raise InvalidTransition(
                f"{job_id}: complete() requires RUNNING, found {job.state.value}"
            )
        deadline = job.heartbeat_at + self.job_timeout_s
        try:
            result = worker(job, deadline)
            if self._clock() > deadline:
                raise TransientError("timeout")
        except TransientError as exc:
            return self._retry_or_fail(job, str(exc))
        except PermanentError as exc:
            self.store.transition(
                job_id, JobState.RUNNING, JobState.FAILED, self._clock(), last_error=str(exc)
            )
            self._job_decision(job, "failed")
            return RunOutcome(job_id, "failed", str(exc), job.attempt)
        finally:
            self._in_flight.discard(job_id)
        self.store.transition(
            job_id, JobState.RUNNING, JobState.COMPLETED, self._clock(), result=result
        )
        self._job_decision(job, "completed")
        return RunOutcome(job_id, "completed", attempt=job.attempt)

    def run_next(self, worker: Worker) -> RunOutcome:
        started = self.start_next()
        if started.status != "running":
            return started
        return self.complete(started.job_id, worker)  # type: ignore[arg-type]

    def drain(self, worker: Worker, max_steps: int = 100) -> list[RunOutcome]:
        outcomes: list[RunOutcome] = []
        for _ in range(max_steps):
            outcome = self.run_next(worker)
            if outcome.status == "idle":
                break
            outcomes.append(outcome)
            if outcome.status == "rejected":
                break  # stop control unavailable: nothing more will start
        return outcomes

    def reclaim_stale(self) -> list[str]:
        """A worker that stopped heartbeating does not hold its job forever."""
        now = self._clock()
        reclaimed: list[str] = []
        for job in self.store.by_state(JobState.RUNNING):
            if now - job.heartbeat_at > self.stale_after_s:
                self._in_flight.discard(job.job_id)
                self.store.transition(
                    job.job_id,
                    JobState.RUNNING,
                    JobState.WAITING,
                    now,
                    attempt=job.attempt + 1,
                    last_error="stale_worker",
                )
                self.queue.enqueue(job.job_id)
                reclaimed.append(job.job_id)
        return reclaimed

    # -- aggregation -----------------------------------------------------------------------
    def aggregate(self, case_id: str) -> dict[str, Any]:
        jobs = self.store.by_case(case_id)
        states = [j.state for j in jobs]
        if any(s is JobState.STOPPED for s in states):
            case_state = "STOPPED"
        elif all(s.terminal for s in states):
            case_state = "COMPLETED" if any(s is JobState.COMPLETED for s in states) else "FAILED"
        else:
            case_state = "IN_PROGRESS"
        return {
            "case_id": case_id,
            "state": case_state,
            "accounts": {
                j.account_id: {"state": j.state.value, "attempts": j.attempt, "error": j.last_error}
                for j in jobs
            },
            "findings": sum(
                (j.result or {}).get("finding_count", 0)
                for j in jobs
                if j.state is JobState.COMPLETED
            ),
        }

    def dead_letters(self) -> list[JobRecord]:
        return self.store.by_state(JobState.FAILED)

    # -- internals ----------------------------------------------------------------------------
    def _retry_or_fail(self, job: JobRecord, error: str) -> RunOutcome:
        now = self._clock()
        failed_attempt = job.attempt
        self.store.transition(
            job.job_id, JobState.RUNNING, JobState.RETRYABLE_FAILURE, now, last_error=error
        )
        if failed_attempt >= self.retry_budget:
            self.store.transition(job.job_id, JobState.RETRYABLE_FAILURE, JobState.FAILED, now)
            self._job_decision(job, "failed")
            return RunOutcome(
                job.job_id, "failed", f"retry_budget_exhausted:{error}", failed_attempt
            )
        self.store.transition(
            job.job_id,
            JobState.RETRYABLE_FAILURE,
            JobState.WAITING,
            now,
            attempt=failed_attempt + 1,
        )
        self.queue.enqueue(job.job_id)
        self._job_decision(job, "retry_scheduled")
        return RunOutcome(job.job_id, "retry_scheduled", error, failed_attempt)

    def _reject(self, identity: RequestIdentity, case: CaseEvent, reason: str) -> AdmissionResult:
        self._emit(Decision("admission", "coordinator", reason, identity, None, None, "case", 0))
        return AdmissionResult("rejected", reason)

    def _job_decision(self, job: JobRecord, outcome: str) -> None:
        self._emit(
            Decision(
                "job",
                "coordinator",
                outcome,
                None,
                None,
                "investigate_account",
                "account",
                0,
                f"attempt={job.attempt}",
            )
        )
