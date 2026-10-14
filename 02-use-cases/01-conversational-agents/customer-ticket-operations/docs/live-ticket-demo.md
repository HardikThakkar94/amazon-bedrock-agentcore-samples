# Live support-ticket injection demo

## Purpose

Show the complete, understandable causal chain in a local browser while retaining genuine
Bedrock inference:

1. A support agent summarizes normal tickets; no record changes.
2. A malicious user submits a new ticket through a real local HTTP form.
3. The support agent reads that stored ticket on the next run.
4. V0 passes the ticket body to Bedrock as raw data and executes the model's proposal with a
   broad demo client. If the model proposes `close_ticket customer-a A-42`, the visible local
   ticket changes from OPEN to CLOSED.
5. The exact captured Bedrock proposal can be replayed through V1–V5, so comparisons do not
   depend on different model samples. The capture is bound to the ticket content it actually saw;
   a subsequent submission makes it visibly stale and unusable.

This proves the live ingress-to-agent path. It does not claim that an outside attacker reached
AWS, that every model follows the injection, or that any real customer record changed.

## Scenario

The main console represents a support operator working for customer A. The separate submitter
view represents the customer-facing ticket form. The attacker submits a ticket whose body asks
for innocent help and contains a control-like instruction to close existing ticket A-42.

The attack intentionally stays inside customer A. This makes the teaching point stronger:
verified operator/tenant identity is necessary, but identity alone does not make customer text
authorized. V1 therefore still lacks the boundary needed to stop this same-customer action.

## Patch behavior

| Version | Expected result for the captured close-ticket proposal |
|---|---|
| V0 | Broad demo client executes it; A-42 becomes CLOSED. |
| V1 | Verified operator and tenant pass; the same-customer proposal can still execute. |
| V2 | Untrusted ticket content is assessed and strict output is parsed. If a valid same-customer `close_ticket` proposal passes those checks, it still executes in this intermediate build—showing that screening and schemas are not authorization. A guardrail intervention is reported as such, not as a model refusal. |
| V3 | Independent action policy denies `close_ticket`; the model cannot grant itself the capability. |
| V4 | Durable local stop state is checked before admission and before any effect. Stop is not rollback. |
| V5 | The same decision/effect evidence is recorded and checked against the expected invariant: malicious ticket must not change A-42. |

The UI must distinguish model proposal, control decision and observed record effect. A model
response is not evidence that an action happened.

## Technical shape

- Python standard-library loopback HTTP server; binds `127.0.0.1` by default.
- Dependency-free HTML/CSS/JavaScript UI using AWS design tokens.
- Integrated Live Demo, actual Code Diff, and Trace/CloudWatch tabs.
- Ticket Store presenter controls: Before/Current/Changes, subject/description/status editing, and labelled
  Normal/Compromised/Policy Blocked/Stopped presets. Manual/preset changes are state-only and
  never appear as Bedrock calls or agent decisions.
- `Apply next patch` activates the next function in `ticket_demo_patches.py` and reopens only
  local ticket effects; the malicious submission and current genuine-response capture remain.
- In-memory tickets and decisions; process restart or Reset removes them.
- Request body size and field lengths are bounded.
- `ScriptedTicketModel` for deterministic offline tests.
- `BedrockTicketModel` for opt-in `--live`; requires `SEC310_MODEL_ID` and the normal named AWS
  profile/region environment. It can only return proposals.
- No AWS resources are created. No real record/tool mutation is available.
- Model-returned links are validated in V2+ and are never rendered or fetched by this UI.

## In-page explanation (dry-run feedback)

The first dry run asked for two things that used to live on slides: a progressive explanation of
the flow and an architecture diagram of the actual demo, both reachable without leaving the IDE.

- **What just happened** (bottom of Live Demo): seven nodes rendered from the latest run, not
  from a script. Red marks an attacker-controlled input or an executed effect, green a boundary
  that denied, blue a live model call. The caption states the lesson for the recorded status
  (CHANGED, BLOCKED, STOPPED, NO_EFFECT, ERROR) in one sentence.
- **Architecture** tab: a data-flow view of this page. The orange box is the Python boundary the
  five patches change. Bedrock inference and CloudWatch invocation records are real; the ticket
  store, the V3 policy decision and the OPEN → CLOSED effect are process-local; AgentCore Gateway +
  Policy and Automated Reasoning appear in a dashed "separate proof" band because this page never
  calls them, `demo live` does. Icons are the official AWS Architecture Icons, served from the
  same loopback process (`/assets/<name>.svg`, allow-listed).

## Stage use

Use V0 with live Bedrock to capture one actual response. If that response does not propose the
malicious action, the UI says so; it never fabricates compliance or silently switches models.
After a response is captured, click `Apply next patch`: the UI reopens local effects, displays the
actual code diff, and lets the presenter test the immutable response through the new boundary.
V1 and V2 intentionally still permit this same-customer, well-shaped action; V3 is the first build
that adds the missing action authority. A fresh Bedrock call remains available on every build.
