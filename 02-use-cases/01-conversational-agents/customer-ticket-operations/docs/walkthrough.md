# Presenter walkthrough — 60-minute code talk

Target: **~48-52 minutes of content, questions interleaved throughout** (code talks have no reserved end Q&A). Two speakers. Terminal font ≥ 18pt (assume the session may be recorded for YouTube).
Every command below is offline and deterministic; rehearse it with Wi-Fi off.

Before going on stage:

```bash
cd sec310-sample && git checkout main && uv sync && uv run pytest && uv run python -m sec310_sample.demo all > /tmp/expected.txt
```

Keep `/tmp/expected.txt` (or the prerecorded capture) as the fallback if a terminal dies. The demo output is
byte-stable across runs, so `diff` against it is a valid check.

Every command below assumes the repo root and a synced `.venv` (`uv sync` once). `uv run` finds the venv
from any subdirectory of the repo.

Tags let you show *diffs*, not just files: `git diff v1-identity v2-untrusted-data --stat`, or
`git show v3-bounded-tools:src/sec310_sample/action_gateway.py`.

---

## 0:00–4:00 · Cold open: the dangerous success

```bash
uv run python -m sec310_sample.demo unsafe
```

Show: `src/sec310_sample/unsafe_agent.py` (fits on one screen). Point at the three sins:
identity from the body, tool data pasted raw, `execute()` on whatever the model said.

Land the thesis: usefulness and safety are independent properties. Then the six-boundary
diagram: `principal → session → model → tool policy → target → state/telemetry`.

## 4:00–9:00 · Two shapes of production agents (slides, no code)

Anonymised case studies: an event-driven, account-scoped investigation **pipeline** and an
authenticated, multi-tenant **copilot**. One emphasises bounded asynchronous autonomy, the
other an interactive trust boundary. Both need the same control plane. Say clearly that the
sample maps their lessons onto current guidance as an interpretation.

## 9:00–17:00 · Patch 1: identity before agency

```bash
git diff v0-unsafe v1-identity --stat
uv run python -m sec310_sample.demo identity
uv run pytest tests/test_identity.py -v
```

Code seams: `identity.py` → `RequestIdentity` (frozen), `GatewayAdapter.identity_from_request`
(token first, body never, conflict = reject), `strip_caller_identity_headers`. `sessions.py`
→ ownership is in the partition key; `authorize_session` on every access.

Nuance to say out loud: execution isolation is not session ownership. Bind the session to the
authenticated user in *your* backend.

## 17:00–25:00 · Patch 2: untrusted data stays data

```bash
git diff v1-identity v2-untrusted-data --stat
uv run python -m sec310_sample.demo untrusted
uv run pytest tests/test_untrusted_data.py tests/test_sync_stream_parity.py -v
```

Code seams: `request_preparation.py` (limits, NFKC, nonce framing, one `build_prompt`),
`guardrails.py` (three-way decision; `LocalGuardrail` is deliberately weak), `schemas.py`
(`extra="forbid"`), `output_validation.py` (links, scope), `assistant.py` (`_prepare` +
`_finalize` shared by `handle_sync` and `handle_stream`; the stream buffers until validated).

The moment: indirect injection sails past the keyword guardrail, the model follows it, and
the deterministic layers still hold. A guardrail result is not a permission.

## 25:00–34:00 · Patch 3: tools encode blast radius

```bash
git diff v2-untrusted-data v3-bounded-tools --stat
uv run python -m sec310_sample.demo tools
uv run pytest tests/test_action_policy.py -v
```

Code seams: `credentials.py` (`READ_SCOPE` vs `WRITE_SCOPE`; note what is *missing*),
`action_gateway.py::_execute` (read the numbered steps aloud), `action_digest` (what a human
actually confirms), `idempotency_key` (derived, never model-chosen), `audit.py`.

The moment: a schema-valid, in-scope, *confirmed* delete is still refused, because the
capability does not exist on this path. Nothing to borrow.

## 34:00–40:00 · Case study A: bounded asynchronous investigation (slides + one file)

Sequence: `case → admission/stop check → per-account FIFO jobs → read-only tools → durable
status → aggregate`. Show `orchestration.py::InvestigationCoordinator.admit` and the
`TRANSITIONS` table. Narrative correction to make: telemetry-only assessment is not enforcement.

## 40:00–45:00 · Case study B: authenticated conversational actions (slides + one file)

Sequence: `authenticated identity → scoped session → framed context → typed plan →
deterministic policy → read/write gateway`. Show `assistant.py::_finalize` and point at the
line where the guardrail-unavailable branch drops writes. Credential custody stays outside the
model-facing process: the model never holds a `CapabilityCredential`.

## 45:00–49:00 · Patch 4: failure containment

```bash
git diff v3-bounded-tools v4-containment --stat
uv run python -m sec310_sample.demo containment
uv run pytest tests/test_failure_modes.py -v
```

Show `docs/failure-policy.md` (the table) and `failure_policy.py::policy_for` (unknown → fail
closed). Then the demo: transient failure → retry → completed; operator stop mid-case →
`STOPPED`; stop store unavailable → nothing starts; overload → `Overloaded(retry_after_s=5)`.

Vocabulary: deployment circuit breaker ≠ runtime safety.

## 49:00–52:00 · Patch 5: telemetry and release gates

```bash
git diff v4-containment v5-telemetry --stat
uv run python -m sec310_sample.demo telemetry
uv run pytest tests/test_behavioral_corpus.py tests/test_telemetry.py -v
```

Show `telemetry.py::Tracer.__call__` (hash, drop `detail`), `Tracer.assert_redacted`
(redaction is a test), `corpus/regression.json` (expectations are tokens). Say: this is
recommended practice; present it as the gate you *should* have, not one you already had.

## Optional · `live`: the same controls against real services (3–4 min, if time and network allow)

```bash
uv run python -m sec310_sample.demo live
```

Needs credentials plus `SEC310_MODEL_ID` / `SEC310_GUARDRAIL_ID` (optional
`SEC310_AR_GUARDRAIL_ID`, `SEC310_CEDAR_POLICY_FILE`); stops with an explicit message
otherwise, and exits 1 if any check was unavailable or any verdict was not the expected one.
Each real call maps to a control the offline stages already proved: `Converse` (proposals
only), `ApplyGuardrail` (three outcomes), `InvokeGuardrailChecks` on a *proposed tool call*
(severity scores; say out loud that the threshold is ours and a missing evaluation is
UNAVAILABLE), `ApplyGuardrail` with an Automated Reasoning policy (formal-logic findings
over the answer text; detect mode), and AgentCore Policy `CreatePolicy` under
`FAIL_ON_ANY_FINDINGS`. The policy step takes the longest: creation is asynchronous and the
gate polls to the terminal state, then prints the service's own `statusReasons` for the
permit-all policy (overly permissive) and for a tool no gateway defines (schema). If you
bring a statement for your own gateway in `SEC310_CEDAR_POLICY_FILE`, the accepted case
shows too. Say: every one of these is a signal the application acts on; none is a
permission; validation is the release gate, enforcement happens at the gateway. Have the
offline recording ready if the network fails; the outcomes are the same, which is the point.
Slot it after Patch 3 or after Patch 5, never in the cold open.

## ~48:00–52:00 · Close, then stay for questions

Slides: the five rules, then Get the code (QR), then Thank you. Questions were taken throughout; close by inviting any remaining ones and staying by the stage.

---

## Speaker split (strawman)

| Segment | Lead | Support |
|---|---|---|
| Cold open, thesis | Hardik | Max runs terminal |
| Two shapes | Hardik: pipeline | Max: copilot |
| Patch 1 identity | Hardik | Max narrates tests |
| Patch 2 untrusted data | Max codes | Hardik interprets threat |
| Patch 3 tools | Hardik policy | Max demo |
| Case study A / B | Hardik / Max | — |
| Patch 4 containment | Max | Hardik |
| Patch 5 telemetry | Hardik | Max |
| Close / Q&A | both | — |

## Failure drills

- Terminal dies → open `/tmp/expected.txt` or the recording; keep talking to the file.
- Laptop dies → second laptop has the repo at the same tag and already `uv sync`ed; `make demo`.
- Question you can't answer → "the sample shows the shape; the specifics depend on your gateway contract."

## Q&A prep

Have crisp answers for: who authenticates the tenant; who authorizes tools; who owns session
state; what fails closed; how streaming is controlled; how releases are behaviourally evaluated;
how this maps to AgentCore Runtime sessions / Identity / Gateway (as interpretation).
