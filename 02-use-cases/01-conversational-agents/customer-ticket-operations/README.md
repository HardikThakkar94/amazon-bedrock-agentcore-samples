# sec310-sample — one agent, five patches

Companion code for the re:Invent code talk **SEC310 · Building Production-Ready Agents Securely**.

> Guardrails are not a system prompt. They are the control plane around identity, state,
> tools, failure modes, and deployment.

A small "security evidence assistant" starts as a prototype that works beautifully and
is trivially dangerous. Five patches turn it into something you could run: not by making
the model smarter, but by putting deterministic controls around it.

Everything here is **synthetic and offline**. Fake tenants, fake accounts, an in-memory
evidence store, a deliberately gullible scripted model. No credentials, no network, no
real service is touched unless you opt in to `--live`, and even then the write path stays
local.

## Run it

```bash
uv sync            # or: pip install -e '.[aws]' pytest
uv run pytest      # 71 tests, < 1s, offline
uv run python -m sec310_sample.demo all     # the full walkthrough
uv run python -m sec310_sample.demo unsafe  # or one stage: identity | untrusted | tools | containment | telemetry
```

Without `uv`: `python3 -m pytest` and `PYTHONPATH=src python3 -m sec310_sample.demo all` (needs `pydantic` and `pytest` installed).

`make check` runs the disclosure scan with built-in patterns. To add an external denylist (kept outside the repo):
`make check DENYLIST=/path/to/denylist.txt` — a missing file is an error, never a silent downgrade.
`scripts/check_tags.sh` proves every tag builds and passes from a fresh checkout.

## The arc

| Tag | Patch | What changes | Proof |
|---|---|---|---|
| `v0-unsafe` | cold open | Identity from the body, tool data pasted into the prompt, model output executed with one wide credential. Works on the happy path. Deletes another tenant's rule when a finding is poisoned. | `tests/test_unsafe_baseline.py` |
| `v1-identity` | Identity before agency | `RequestIdentity` derived from a verified token at the gateway; caller-supplied identity is rejected when it conflicts; session ownership lives in the storage key. | `tests/test_identity.py` |
| `v2-untrusted-data` | Untrusted data stays data | One `PreparedRequest` for sync and stream; hard limits; nonce framing; guardrail with an explicit `NONE / INTERVENED / UNAVAILABLE` branch; typed output with allow-listed arguments; deterministic link and scope validation; failure policy table; a telemetry sink that can fail without failing the request. | `tests/test_untrusted_data.py`, `tests/test_sync_stream_parity.py`, `tests/test_output_validation.py` |
| `v3-bounded-tools` | Tools encode blast radius | Separate read and write capabilities; no delete capability exists on the conversational path; confirmation bound to the exact action digest; idempotency; hash-chained audit. | `tests/test_action_policy.py` |
| `v4-containment` | Design the stop path before autonomy | Operator stop checked before admission and every job; conditional state transitions; FIFO with dedup; retry budget; timeout → retryable; stale-worker reclaim; bounded concurrency with an explicit overload signal. | `tests/test_failure_modes.py` |
| `v5-telemetry` | Observe decisions, gate releases on behaviour | Keyed-hash, versioned `DecisionEvent`s; identity-derived raw values are scrubbed at runtime and the redaction is also enforced by test; a versioned behavioural corpus run as a release gate. | `tests/test_telemetry.py`, `tests/test_behavioral_corpus.py` |

`git diff v1-identity v2-untrusted-data --stat` shows exactly what each patch touched.

## Five production rules

1. **Identity stays outside the model.** Authenticate before inference; carry an immutable identity into every state and tool boundary.
2. **Sessions are authorization domains.** A random session id is not authorization. Bind state to tenant and principal; check ownership on every access.
3. **Guardrails are layers, not permissions.** Input screening, prompt-attack detection, framing, typed output, deterministic validation, and action authorization are different controls. A guardrail pass authorizes nothing.
4. **Tools encode blast radius.** Separate read and write authority. Validate target and state. Require a deterministic confirmation for consequential mutations. Don't mint capabilities you never want borrowed.
5. **Design the stop path before autonomy.** Failure direction per dependency, bounded execution, retry budgets, idempotency, kill switches, known terminal states, versioned telemetry, and behavioural regression tests.

## Map

```
src/sec310_sample/
  unsafe_agent.py         v0  the cold open
  identity.py             P1  RequestIdentity, FakeAuthenticator, GatewayAdapter
  sessions.py             P1  ownership in the key
  request_preparation.py  P2  limits, normalisation, nonce framing, one prompt builder
  guardrails.py           P2  Local / Unavailable / Bedrock guardrails, three-way decision
  schemas.py              P2  ActionPlan, AssistantResponse (pydantic, extra=forbid)
  output_validation.py    P2  links and proposals validated deterministically
  assistant.py            P2  sync + stream share one pipeline
  failure_policy.py       P2  the fail-open / fail-closed table
  credentials.py          P3  scoped, expiring capability credentials
  action_gateway.py       P3  reach → capability → confirmation → state → policy → idempotency → execute → audit
  audit.py                P3  hash-chained append-only log
  orchestration.py        P4  stop control, durable job store, FIFO, coordinator
  decisions.py            P2  Decision objects emitted by every control; GuardedSink (tracing degrades, never fails)
  telemetry.py            P5  Tracer: keyed hashes, runtime scrub, versioned, redaction-tested
  evaluation.py           P5  corpus runner
  model.py                    ScriptedModel (offline, gullible) + optional BedrockModel
  tools/                      EvidenceStore, GodModeClient (v0), ReadClient, WriteClient
  demo/                       python -m sec310_sample.demo
fixtures/                     synthetic evidence + adversarial request fixtures
corpus/regression.json        versioned behavioural expectations
docs/walkthrough.md           segment-by-segment presenter map
docs/failure-policy.md        the decision table, explained
scripts/scan_identifiers.py   disclosure scan (run before publishing anything)
scripts/check_tags.sh         every tag builds + passes from a fresh checkout
scripts/live_setup.sh         AWS resources for the live stage (guardrails, AR policy); prints exports
scripts/live_teardown.sh      removes them, plus any sec310_demo* policy engine left behind
scripts/live_gateway.py       up/down: gateway + Lambda tools + policy engine (ENFORCE) + Cedar/Dogwood policies
scripts/live/                 the AR policy's natural-language source and the tool Lambda's code
```

## Live mode (optional)

```bash
export SEC310_MODEL_ID=<a Bedrock model id you are entitled to>
export SEC310_GUARDRAIL_ID=<guardrail id>  SEC310_GUARDRAIL_VERSION=DRAFT
uv run python -m sec310_sample.demo tools --live
```

The live model only produces *proposals*. The gateway, the fixtures, and the write path
are unchanged and local. If the network is down, run without `--live`; the outcomes are
the same, which is rather the point.

### The `live` stage: the same controls against real services

```bash
uv sync --extra aws                                   # boto3 with the agentic guardrail and policy APIs
eval "$(sh scripts/live_setup.sh)"                    # guardrails + an Automated Reasoning policy (~2 min); exports their ids
eval "$(uv run python scripts/live_gateway.py up)"    # gateway + tool Lambda + policy engine in ENFORCE (~1 min); exports its URL
uv run python -m sec310_sample.demo live
uv run python -m sec310_sample.demo observe           # a few minutes later: the engine's own decision counts from CloudWatch
uv run python scripts/live_gateway.py down            # removes the gateway, engine, policies, function, roles
sh scripts/live_teardown.sh                           # removes the guardrails and the AR policy
```

`live` is not part of `all`. It needs credentials in the default AWS SDK chain plus the
variables the setup script prints (`SEC310_MODEL_ID`, `SEC310_GUARDRAIL_ID`,
`SEC310_AR_GUARDRAIL_ID`). It stops with an explicit message (exit 2) when they are missing (`SEC310_GATEWAY_URL` is optional and
switches on the enforcement step),
and exits 0 only when every check ran and every outcome was the expected one; an unavailable
dependency or an unexpected verdict is listed under "Live proof incomplete" with exit 1. A
live proof that proved nothing must not look like one that did. Everything below was run
against a real account on 2026-10-08 (us-east-1); the whole stage takes about 75 seconds.

| Call | Control it proves | Code |
|---|---|---|
| `bedrock-runtime:Converse` | the model proposes; it does not act. The typed shape is requested with a forced tool call whose schema *is* the sample's pydantic model, then validated again on the way back | `model.BedrockModel` |
| `bedrock-runtime:ApplyGuardrail` | guardrail on model I/O with three outcomes, branched on all three | `guardrails.BedrockGuardrail` |
| `bedrock-runtime:InvokeGuardrailChecks` | prompt-attack severity scores for the argument *values* of a proposed tool call, before it runs; the threshold is the application's, and a missing evaluation is UNAVAILABLE, not a pass | `live.GuardrailChecks` |
| `bedrock-runtime:ApplyGuardrail` (AR policy) | formal-logic findings over the answer text: a claim the team's rule-change policy contradicts comes back `INVALID` with the rule it breaks, a supported claim `VALID`; `action` is `NONE` both times (detect mode) | stage code |
| `bedrock-agentcore-control:CreatePolicy` under `FAIL_ON_ANY_FINDINGS` | Cedar is machine-checked before anything could enforce it: the parser refuses an unconstrained resource synchronously; everything else settles asynchronously to `ACTIVE` or `CREATE_FAILED` with `statusReasons`, and the gate reads the verdict from that terminal state | `live.CedarPolicyGate` |
| `cloudwatch:GetMetricData` on `AWS/Bedrock-AgentCore` (`demo observe`) | the platform's own record of what the engine decided: ALLOW / DENY / deny-by-default per engine and per policy, published with no instrumentation — the hashed decision events of Patch 5, emitted for you | `live.PolicyObserver` |
| signed MCP `tools/call` to an AgentCore Gateway with a policy engine in `ENFORCE` | **Cedar and Dogwood deciding real tool calls**: a Cedar `forbid` keeps writes inside one account, and a Dogwood temporal `permit` allows a write only after the same policy session read that account's evidence; the same `update_rule` call is DENY, then ALLOW, then DENY, and a request without a session id is rejected outright | `live.GatewayClient`, `scripts/live_gateway.py` |

Two things the live run taught us, both encoded in the code: the prompt-attack classifier
scores an instruction-shaped wrapper such as `proposed tool call: ...` as an attack on its own
(0.8), so only the argument values are screened; and a capable model wraps JSON in a Markdown
fence unless the shape is requested at the API, so the live model is asked for it with a
forced tool call. Validation stays strict either way.

The policy step creates a throwaway engine with no gateway attached and expects four
rejections with the service's own reasons: `permit(principal, action, resource);` from the
parser (wildcard resource), `permit(... resource is AgentCore::Gateway)` from semantic
validation (overly permissive), its `forbid` twin (overly restrictive), and a policy that
conditions on `context.input.account_id` from the schema check (no attached gateway defines
it). Accepted, *enforced* policies live on the engine that `scripts/live_gateway.py` attaches to
a real gateway (AWS_IAM inbound auth, one Lambda target with `read_evidence` and `update_rule`).
Three things the service taught us there, all encoded in the script: an unconditional `permit`
for a tool is flagged "Overly Permissive", so the read permit names the account space it covers
(`like "acct-*"`); permits combine with OR, so an account scope written as a second permit let
writes to other accounts through once anything had been read, and the scope is a `forbid`; and
validation is engine-wide, so that `forbid` is "Overly Restrictive" until a write permit exists,
which fixes the creation order. Engine and policy names must match `^[A-Za-z][A-Za-z0-9_]*$`
while gateway names take hyphens and refuse underscores; the scripts know. Temporal policies
need the `x-amzn-bedrock-agentcore-policy-session-id` header on every call, and changing a
temporal policy invalidates open sessions. Transport and
service failures are raised as `PolicyGateError`, never reported as a verdict. Cleanup waits
for each deletion to be confirmed and prints anything it could not remove.

`--live` on the other stages uses the real model for proposals while the write path stays
local. A real model is not the scripted gullible one: it may decline the injected instruction,
so those stages say what actually happened instead of narrating the scripted outcome, and
the behavioural corpus (`telemetry` stage) is the deterministic regression gate and always runs
on the scripted model, which its events say. Run on 2026-10-09 with Haiku 4.5, Sonnet 5, Opus 5
and Opus 5.5 (`global.anthropic.*` inference profiles, us-east-1): all four pass `live` and
`all --live`; none followed the injection. Three model differences are handled explicitly in
`model.BedrockModel`: the typed shape is requested as a forced tool call with every field
required (Sonnet 5 otherwise omits empty lists), a forced tool choice falls back to `auto` only
when the service rejects it (Opus 5.5), and a `max_tokens` stop is handed to the strict parser
as a truncated, malformed reply rather than an empty one.

Unit tests use `botocore.stub.Stubber` and small fake clients and run offline (the stage runs
end to end against fakes); `SEC310_LIVE=1 uv run pytest tests/test_live_services.py` adds
two real-service tests for a throwaway account.

## What this sample is not

It is not a framework, not a reference architecture, and not a claim about any specific
production system. It is the smallest code that makes each control concrete enough to
argue about.

## License

MIT-0. See `LICENSE`.
