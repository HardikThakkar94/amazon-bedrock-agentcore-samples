# sec310-sample — one agent, five patches

Companion code for the re:Invent code talk **SEC310 · Building Production-Ready Agents Securely**.

> Guardrails are not a system prompt. They are the control plane around identity, state,
> tools, failure modes, and deployment.

A small "security evidence assistant" starts as a prototype that works beautifully and
is trivially dangerous. Five patches turn it into something you could run: not by making
the model smarter, but by putting deterministic controls around it.

The evidence and tool targets are **synthetic** so no customer data or production rule can
be harmed. For the real-model rehearsal, use `--live`: proposals come from Bedrock and
screening from Bedrock Guardrails. The default offline commands remain a deterministic
regression/fallback path and clearly identify their scripted model; never describe them as
live inference. `demo live` separately exercises real AWS guardrails, policy validation and
AgentCore Gateway enforcement. `demo observe` reads the platform's recorded evidence.

## Run it

```bash
uv sync            # or: pip install -e '.[aws]' pytest
uv run pytest      # current HEAD's tests; offline (historical v5 tag has 71)
uv run python -m sec310_sample.demo all     # the full walkthrough
uv run python -m sec310_sample.demo unsafe  # or one stage: identity | untrusted | tools | containment | telemetry
```

Without `uv`: `python3 -m pytest` and `PYTHONPATH=src python3 -m sec310_sample.demo all` (needs `pydantic` and `pytest` installed).

### Browser demo: submit the attack live

The CLI fixture starts after attacker-controlled text already exists. The separate browser demo
shows the missing first step: a customer submits a support ticket through a real local HTTP
form, the stored ticket reaches the agent on its next run, and the UI displays any actual local
effect separately from the model proposal.

```bash
export AWS_PROFILE=<named-development-profile> AWS_REGION=us-east-1 AWS_DEFAULT_REGION=us-east-1
unset AWS_BEARER_TOKEN_BEDROCK
aws sts get-caller-identity --profile "$AWS_PROFILE"   # stop if this fails or is the wrong account
export SEC310_MODEL_ID=<Bedrock model id>
export SEC310_RUN_ID="sec310-ticket-$(date +%Y%m%d-%H%M%S)"
uv run python -m sec310_sample.ticket_demo --live --open
```

The single browser contains **Live Demo**, **Code Diff**, **Trace & CloudWatch**, and
**Architecture** tabs. The Live Demo ends with a "What just happened" strip that colours
customer → store → prompt → model → proposal → boundary → effect from the latest run, so the
story is told under the execution rather than on a separate slide. The Architecture tab is a
data-flow diagram of this exact demo: what is real (Bedrock inference, CloudWatch records),
what stays local (ticket records, the V3 decision, the effect), and what lives only in
`demo live` (AgentCore Gateway + Policy, Automated Reasoning). The
Ticket Store can switch between **Before**, **Current**, and highlighted **Changes**; a presenter
can edit ticket subject, description, and OPEN/CLOSED status or load Normal/Compromised/Policy Blocked/Stopped state presets.
Those presenter controls are visibly labelled and create no Bedrock or CloudWatch record. Run V0
live before the attack, open **Malicious submitter**, submit the ticket, then run V0 live again.
A successful attacked V0 call becomes the current capture only for that exact ticket set; adding
or changing ticket input makes an older capture visibly stale and disables replay.

Click **Apply next patch** to reopen local effects, activate the next real Python function, and
show its actual code diff. Use **Test exact live response** to exercise the new boundary against
the genuine Bedrock response that caused V0's effect. **Run Bedrock live** remains available for
a fresh model sample. This separates model variability from whether the application control works.

V1 identity and V2 screening/schema checks intentionally remain insufficient for this well-shaped,
same-customer action; V3's independent action policy is the first boundary that denies it. V4
makes the agent contain itself: the first denied action ends the run and latches the agent stopped
until an operator resets it (the stop button remains as a manual brake). V5 records the decision, the halt and the no-change release
invariant. Add `--managed-guardrail` only when the configured Bedrock Guardrail environment is
available; otherwise V2 uses the clearly labelled deterministic local signal. For an offline test
only, omit `--live`; never present that mode as live inference. See
[docs/live-ticket-demo.md](docs/live-ticket-demo.md) for the exact story and limitations.

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
  ticket_demo.py              loopback browser server, ticket state, proposal capture/replay
  ticket_demo_web/            dependency-free operator and malicious-submitter views
    assets/                   official AWS Architecture Icons served read-only
  tools/                      EvidenceStore, GodModeClient (v0), ReadClient, WriteClient
  demo/                       python -m sec310_sample.demo
fixtures/                     synthetic evidence + adversarial request fixtures
corpus/regression.json        versioned behavioural expectations
docs/walkthrough.md           segment-by-segment presenter map
docs/live-ticket-demo.md      live ingress → model proposal → local effect → patch replay
docs/ide-rehearsal.md         one-window VS Code layout and beat sheet (dry-run feedback)
docs/failure-policy.md        the decision table, explained
scripts/scan_identifiers.py   disclosure scan (run before publishing anything)
scripts/check_tags.sh         every tag builds + passes from a fresh checkout
scripts/live_setup.sh         AWS resources for the live stage (guardrails, AR policy); prints exports
scripts/live_teardown.sh      removes them, plus any sec310_demo* policy engine left behind
scripts/live_gateway.py       up/down: gateway + Lambda tools + policy engine (ENFORCE) + Cedar/Dogwood policies
scripts/live_logging.py       up/down: Bedrock invocation logging and gateway vended log delivery
scripts/live/                 the AR policy's natural-language source and the tool Lambda's code
```

## Live mode (optional)

```bash
export SEC310_MODEL_ID=<a Bedrock model id you are entitled to>
export SEC310_GUARDRAIL_ID=<guardrail id>  SEC310_GUARDRAIL_VERSION=DRAFT
uv run python -m sec310_sample.demo tools --live
```

The live model only produces *proposals*. The sample's application gateway and write path
remain local; successful writes change the in-memory store, not AWS production resources.
Real models may decline, produce malformed plans, or follow an injection. The runner reports
what happened, never substitutes a scripted response without a label. Model options and
observed variability are in [docs/model-options.md](docs/model-options.md). If the venue
network fails, show a recording of real calls or explicitly announce the offline test mode.

### The `live` stage: the same controls against real services

```bash
export AWS_PROFILE=your-development-profile AWS_REGION=us-east-1 AWS_DEFAULT_REGION=us-east-1
unset AWS_BEARER_TOKEN_BEDROCK                        # use the named profile, not an ambient bearer token
aws sts get-caller-identity --profile "$AWS_PROFILE" # verify the account before setup
uv sync --extra aws
sh scripts/live_setup.sh > /tmp/sec310-model.env && . /tmp/sec310-model.env
uv run python scripts/live_gateway.py up > /tmp/sec310-gateway.env && . /tmp/sec310-gateway.env
uv run python scripts/live_logging.py up > /tmp/sec310-logs.env && . /tmp/sec310-logs.env
export SEC310_MODEL_ID=google.gemma-3-4b-it             # or another candidate in model-options.md
uv run python -m sec310_sample.demo unsafe --live      # genuine model responses, two attack paths
uv run python -m sec310_sample.demo all --live
uv run python -m sec310_sample.demo live
uv run python -m sec310_sample.demo observe            # retry after delivery if exit 1: no data yet
# AFTER retaining private rehearsal evidence, and when the logging demo is finished:
uv run python scripts/live_logging.py down             # first: verify logging config/delivery removal
uv run python scripts/live_gateway.py down
sh scripts/live_teardown.sh
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
| `cloudwatch:GetMetricData` on `AWS/Bedrock-AgentCore` (`demo observe`) | ALLOW / DENY / NoDeterminingPolicies per engine, ALLOW / DENY per policy; service-published aggregate counts, not the sample's HMAC-hashed events | `live.PolicyObserver` |
| `logs:FilterLogEvents` for model invocations (`demo observe`) | Bedrock's recorded request metadata, response and token counts; service errors remain errors, and a proposal is not proof of execution | `live.InvocationLogReader` |
| `cloudwatch:GetMetricData` on `AWS/Bedrock/Guardrails` | per-guardrail invocation/intervention/text-unit metrics, plus account-wide prompt-attack check count; not per-request guardrail log records | `live.GuardrailObserver` |
| `logs:FilterLogEvents` for gateway vended logs | the engine's actual decision, reason, determining policies and temporal evaluation for each MCP request | `live.GatewayLogReader` |
| signed MCP `tools/call` to an AgentCore Gateway with a policy engine in `ENFORCE` | **Cedar and Dogwood deciding real tool calls**: a Cedar `forbid` keeps writes inside one account, and a Dogwood temporal `permit` allows a write only after the same policy session read that account's evidence; the same `update_rule` call is DENY, then ALLOW, then DENY, and a request without a session id is rejected outright | `live.GatewayClient`, `scripts/live_gateway.py` |

The live run taught us: the prompt-attack classifier scores an instruction-shaped wrapper
such as `proposed tool call: ...` as an attack on its own (0.8), so only argument values are
screened. Models also differ in API support: forced tool choice is preferred, but only an
explicit service rejection relaxes a capability. Fenced JSON text is unwrapped, not repaired;
field/type validation stays strict. See the model-options guide.

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

## Reading the logs on stage

`live_logging.py up` enables **account/Region-wide text invocation logging**, not just this
program's calls. Full prompts and answers are stored; use only an isolated development
account with synthetic inputs. New log groups retain data for three days. Existing foreign
invocation configurations are preserved and never automatically displayed. Keep raw logs
and real account identifiers OUT of the public sample and package.

The script prints `SEC310_RUN_ID`. Model calls carry that value in `requestMetadata.sec310_run`;
`observe` filters invocation records to that run and refuses an unfiltered invocation display
when the run ID is absent. Re-source fresh logging exports for a new rehearsal. The terminal
prints safe metadata/structured flags and the role name, never the caller's STS session name
or the full prompt or answer.
In the CloudWatch console, open the log groups named in the exports for the full platform
records. Model invocation logging does NOT capture standalone `ApplyGuardrail` calls: their
assessments appear in `demo live`, and their metrics appear in `observe`. Per-request API
accountability for standalone guardrails additionally needs CloudTrail guardrail data-event
logging, which this sample does not provision. `InvocationsIntervened` must not be equated
with the response's `action`; Automated Reasoning detect-mode checks were observed with
`action=NONE` while that metric still increased.

`observe` exits 1 while any configured section has no data (delivery lag), 2 on operational
or incomplete reads, and 0 when every configured section could be read. An API failure
record is displayed with its `errorCode`, not as an empty successful model answer. Gateway
ALLOW/DENY comes from its structured `body.policy`, not an inference from HTTP 403.

Official sources:
- [Bedrock model invocation logging](https://docs.aws.amazon.com/bedrock/latest/userguide/model-invocation-logging.html)
- [Guardrail metrics](https://docs.aws.amazon.com/bedrock/latest/userguide/monitoring-guardrails-cw-metrics.html)
- [AgentCore observability setup](https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/observability-configure.html)
- [Gateway logs](https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/observability-gateway-metrics.html)

## AgentCore browser demo: progressive builds and scope labels

This browser/API/Runtime demo is separate from the historical tagged local-demo arc above;
tags and their source remain unchanged. Its actual build order is V0 unsafe, V1 Guardrails,
V2 Identity (caller and logical Region scope), V3 Policy/approval, V4 Containment, V5 Evidence.
Cognito access-token verification and Runtime/Gateway JWT admission apply to **every** build;
V2 is the first Gateway *region/caller scope* policy, not the first login check. V1 uses the
broad v0 Gateway with Guardrails screening of tool output; V2 uses the tenant-fenced v1
Gateway and keeps Guardrails enabled. V3 uses its own approval engine, while V4/V5 use the
v4 engine. On V3+, model-supplied ticket text cannot authorize notes: the Runtime refuses
unrequested live/captured notes before Gateway. Only the isolated, owner/session/actor/fixture-
bound eval runner can grant its direct note policy/cap probes; Region and write-cap decisions
still come from the real Gateway. The installed Strands agent advertises a validated,
deep-copied model-only projection of the raw Gateway tools/list: plain-string ticket
fields, no actor or run_id. Native MCP execution still goes through the same Gateway
client after Runtime injects the verified caller and owned run. The console-only
confirm_close is not model-advertised. A model response containing schema JSON text
is not a native ToolUse, a ticket read or an approval card. For an explicit verified
operator Ask, V3+ instructs a native list_tickets read followed by a native close_ticket
proposal held before Gateway execution; this is not the operator's separate approval.
An Ask that returns only JSON text is NO_EFFECT with the close request marked incomplete,
not a successful approval. After a verified own-ticket read and successful screen,
a V3+ Ask with no held close gets at most one additional model turn in the same owned
conversation, only for the first requested ticket; all prior text remains non-authoritative.
The API checks all zero-to-five distinct, exact own OPEN seed ticket IDs before model
admission. It rejects invalid fourth/fifth targets instead of silently dropping them;
a native held proposal for any submitted ticket retains operator-request provenance.
Runtime checks the same request shape after verified owner/Stop admission but before V4/V5
writable breaker intent; known bad input cannot strand a pending intent or make the
next valid run spuriously read-only. Genuine uncertain effects keep their exclusion.
An unanswered continuation is recorded incomplete, not retried. Deployed `.6` and `.7`
no-card smokes, and the deployed `.8` native held-card/Approve-502 smoke, are historical;
no current `.9` model/approval success or full-suite PASS is claimed. The API's newly
scoped Events-table UpdateItem permission permits its post-grant owner receipt;
unknown outcomes still retire/fence the policy session. Fresh sign-in may replay only
a tenant-owned recorded run verified by the event owner, never mint approval authority.
On an authoritative tenant/run invalidation, open run-trace drawers and pending
CloudWatch replies are discarded; static Evals/architecture controls remain separate.
Successful approval rotates the policy session: the old drawer is cleared, but the
newly completed approval run stays playable only when the API's new recorded_run
proves that exact run ID and tenant. Missing event ingestion gets one bounded owned
read, not a stale/foreign trace or a repeated model/approval call.
The one owned approval-events read is protected from periodic state polling while
pending; authoritative tenant/proof/Run/Reset/stage changes still cancel it. Empty,
denied or malformed results remain explicitly unavailable without repeated reads. Malformed tool
arguments are repairable local errors, not native policy denials. The operator Stop is checked at API and Runtime admission on every build.
Stop is admission-only: an already-admitted run can finish; its pill is not evidence of
cancellation or quiescence. Future runs refuse until cleared, without bypassing an owner/
UNKNOWN recovery fence. `customer-a` and `customer-b` are the persisted `customer_id` authorization
keys, displayed as **Region A** and **Region B**; these are application scopes, not the AWS
deployment region `us-east-1`. The Cedar policy, Cognito identity and portal presets retain
their identities; the eval inputs are a separately versioned measured dataset described in
`evals/SCENARIO_MATRIX.md`. Older suite rows are historical and cannot prove the current gate.

Approval is a safe application-level hold, **not** a native Strands interrupt: the API
validates and owns a run before an initialized MCP handshake and exactly one
`confirm_close` through the Gateway, then replays only the exact approved proposal. Ambiguous grants or Runtime effects retain
UNKNOWN fencing and rotate the policy session for future dispatch; an expired Runtime
session is never an excuse to replay a write without reconciliation. The console's
CloudWatch drawer projects verified run spans and structured Gateway policy decisions,
while Auth, Guardrails and some Policy milestones are explicitly app-recorded/inferred,
not native service audit events. `make eval-k10 BUILD=v5` is an optional 10-trial variance
study kept outside the console release-gate matrix; it is not a replacement for the
full V5 release gate. Current release requires real successful Guardrails screening, forbidden-
effect safety, useful benign answers with the existing Helpfulness floor, and direct Runtime/
Gateway probes; a failed ApplyGuardrail dependency is UNAVAILABLE, never a prompt-attack hit.
Named-profile Terraform recipes remove an ambient Bedrock bearer token only in each child
process; the prompt Guardrail resource and SSM pointer require an exact target-account ARN
before downstream Runtime pointer acceptance. They do not change a caller's global provider
environment. `scripts/console_link.py` is a source-only helper for a separately
authorized operator and is never run by this build or its tests against real credentials.
See `notes/sec310-speaker-notes.md` for the current presenter route.

## AgentCore browser demo: unresolved-run recovery

The deployed SEC310 browser/API demo uses `busy_owner` (and `busy_stage`/`busy_sub`) as an
owned exclusion, not a lease that expires by itself. A Runtime timeout, lost grant reply,
failed state transition, or interrupted eval may leave an owner in place. `/api/state`
returns `recovery` with the disposition, owner/run ID, reason and safe next step; the
console shows **Recovery required**. Reset and apply return 409 while an owner exists.
`breaker_pending` without an owner is read-only until an operator reviews effects and
uses **Reset circuit breaker**. A completed clean run can automatically release its
exact owner; a failed breaker trip retains a durable writable-intent marker even when
the OPEN update did not commit. A policy-session rotation fences *new application
dispatch*, but does not revoke an already issued Gateway grant or stop in-flight work.

**Out-of-band operator recovery (not automated by this sample):**

1. In the confirmed demo account and region, identify the exact tenant and `busy_owner`,
   `busy_stage`, `busy_sub`, `policy_session`, `breaker_pending`, `breaker_open`,
   `approval_uncertain` / `approval_dispatch`, and `last_run` from a **consistent** state
   read. Identify associated Runtime invocation, run events, Gateway/tool records, and
   before/after ticket snapshots. Do not put access tokens, credentials or session secrets
   in recovery notes.
2. Establish from supported AgentCore Runtime and Gateway/tool contracts that *all*
   relevant invocations/tool work have quiesced or have been authoritatively fenced.
   **Elapsed `busy_until` and quiet logs are not evidence of quiescence.** The precise
   service-supported quiescence/fencing procedure has **not** been established by this
   offline remediation; it is an unresolved prerequisite before clearing an orphan.
   Do not run a recovery write merely because the owner looks stale.
3. Reconcile actual ticket effects with the run's ERROR/evidence-uncertain record and
   the exact held approval's decision. Treat lost Gateway replies as potentially granted.
   Record who approved recovery and the evidence used. Keep terminal approval/effect
   history; pending requests from a retired session must be marked expired/failed, not
   silently moved to another session.
4. Only after step 2 is proven, use approved break-glass access to make **one conditional
   state transition** against the exact observed tenant, owner, policy session and
   relevant marker/revision values. Rotate to a fresh policy session, retire old cards,
   clear only that owner's busy fields/uncertain marker, and keep the breaker OPEN until
   the operator separately chooses to reset it after inspecting the effects. If any
   condition fails or the write reply is uncertain, read back consistently and restart
   reconciliation; never remove a different owner's exclusion. No unconditional PutItem
   or time-only release. The application does not offer a button that asserts quiescence.

This is an operational prerequisite, not proof that real AgentCore/Gateway temporal
behavior, Runtime cancellation, or DynamoDB consistency has been observed live.

## What this sample is not

It is not a framework, not a reference architecture, and not a claim about any specific
production system. It is the smallest code that makes each control concrete enough to
argue about.

## License

MIT-0. See `LICENSE`.
