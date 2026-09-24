# Failure policy: the table is the design

"Graceful degradation" is not a policy. This is:

| Dependency | Policy | Why |
|---|---|---|
| Identity envelope (token verification) | fail closed | Without a verified identity there is no scope to enforce. Reject. |
| Session ownership store | fail closed | Cannot prove the caller owns the session → cannot serve it. |
| Mutation authorizer / policy | fail closed | A write with unknown policy is a write with no policy. |
| Confirmation | fail closed | No confirmation, no consequential action. `confirmation_required` is a *result*, not an error. |
| Operator stop control | fail closed | If we cannot read the kill switch, we must assume it is pulled. Nothing privileged starts blind. |
| Guardrail | degraded read-only | Reads may continue and the response says so; any write proposal is dropped with `fail_closed:guardrail_unavailable`. |
| Tracing sink | degraded read-only | `GuardedSink`: a raising sink drops the event and counts it; the request continues. |
| Optional read tool *(pattern, not in this sample)* | degraded read-only | Remove the capability for this request and disclose degraded mode. Worth doing; the sample has no optional tool to demonstrate it on. |
| Downstream overload | retry bounded | Explicit `Overloaded(retry_after_s)`; the caller backs off; nothing piles up. |
| Worker timeout | retry bounded | Timeout becomes `RETRYABLE_FAILURE`, then `WAITING` (attempt+1) or `FAILED` when the budget is spent. |

Unknown dependency → **fail closed**. `policy_for()` returns `FAIL_CLOSED` for anything not
in the table, so forgetting to classify a dependency is never a licence to fail open.

## Vocabulary

- **Deployment circuit breaker** (rollback on bad deploy) is a release control.
- **Runtime safety** is kill switches, backpressure, timeouts, retry budgets, bounded execution.
- A **terminal state** is one an operator can inspect, stop, replay, or remediate: `COMPLETED`, `FAILED`, `STOPPED`.

## Where it is enforced

- `assistant.py` — guardrail `UNAVAILABLE` branch applies `DEGRADED_READ_ONLY`.
- `decisions.py::GuardedSink` — tracing failures drop events, never requests (wrapped by every component).
- `orchestration.py` — stop control unavailable → reject; overload → `Overloaded`; timeout → retry budget.
- `action_gateway.py` — confirmation, capability, and state checks all reject by default.
- `failure_policy.py::policy_for` — unknown dependency → fail closed.
- Tests: `test_failure_modes.py::test_policy_table_pins_the_behaviour_it_documents` pins table ↔ behaviour;
  `test_untrusted_data.py` covers the guardrail and tracing rows; `test_failure_modes.py` covers stop,
  overload, timeout, and retry budget. The optional-read-tool row is a design pattern, not code here.
