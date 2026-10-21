# Plan: move the ticket agent to Strands on AgentCore (branch `feature/agentcore-strands-terraform`)

Goal: every control the browser demo shows is enforced by a real AWS service, not a local Python
`if`, while the presenter UI, the patch-by-patch story and the exact-response replay stay intact.

## Today vs target

| Piece | Today (local) | Target |
|---|---|---|
| Agent loop | `BedrockTicketModel` + `DemoState._run_snapshot` in `ticket_demo.py` | Strands `Agent` on **AgentCore Runtime** (code zip from S3, `python3.12`) |
| Tickets | in-memory dict | DynamoDB table behind a ticket-tools Lambda |
| Tools | none; effects applied in-process | `list_tickets`, `close_ticket`, `add_note` as an **AgentCore Gateway** Lambda target (MCP) |
| Identity (V1) | hard-coded `customer-a` | Cognito user pool → JWT; Runtime `custom_jwt_authorizer`; customer from claims; policy session = id + identity |
| Screening (V2) | `ApplyGuardrail` in the pipeline + Pydantic | Strands `BedrockModel(guardrail_id=…)` on input/output + structured output; nonce-tagged untrusted blocks |
| Policy (V3) | `if operation == "close_ticket"` | **AgentCore Policy** (Cedar `forbid close_ticket` for the summary task) at the Gateway; optional Dogwood `confirm_close` before close |
| Contain (V4) | in-memory `stop_requested` | Strands hook: first DENY ends the run; durable stop flag (AppConfig or DynamoDB) checked at Runtime entry, fails closed; max-turns cap |
| Evidence (V5) | single-run invariant | AgentCore Observability traces → **AgentCore Evaluations**: dataset eval with a code-based "no forbidden effect" evaluator + LLM judge; release gate; online eval + alarm |
| Automated Reasoning | `demo live` only | Gateway REQUEST **interceptor** Lambda: `ApplyGuardrail` with the AR guardrail on write arguments; block on `invalid` |
| Infra | boto3 scripts | Terraform under `infra/` (this branch) |

The presenter UI (`ticket_demo_web/`) stays a local page; its server calls `InvokeAgentRuntime`
instead of Converse, and reads ticket state from DynamoDB.

## Phases

0. **Infra parity (done on this branch).** `infra/` reproduces `live_setup.sh`, `live_gateway.py`
   and `live_logging.py` with the same resource names. `make validate` and `make plan-*` pass.
   Remaining: apply in a clean account and run `demo live` against it.
1. **Ticket tools behind the Gateway.** DynamoDB table + Lambda target + Cedar policies. Local
   agent still, but every effect is a real `tools/call`; V3's DENY is the Gateway's `-32002`.
2. **Strands agent, local.** Replace `BedrockTicketModel` with a Strands agent using the Gateway
   as an MCP tool provider. Keep `ScriptedTicketModel` for offline rehearsal.
3. **Host on AgentCore Runtime.** S3 code artifact + `aws_bedrockagentcore_agent_runtime`
   (new `infra/iac/roots/runtime`). Cognito + JWT authorizer for V1.
4. **Real V4.** Durable stop (fails closed) + Strands hooks; CloudWatch alarm on policy-deny rate.
5. **Evaluations.** OTel spans → CloudWatch; `aws_bedrockagentcore_evaluator` (code + LLM judge),
   dataset of benign/attack cases, `make eval` as the V5 gate; `online_evaluation_config`.
6. **AR interceptor** on `update_rule`/`close_ticket` (optional segment).

## Open decisions

- **Per-build controls.** The demo switches builds live. Options: (a) one policy set per build,
  swapped by "Apply next patch" (policy changes invalidate sessions — fine, but adds seconds);
  (b) Cedar conditioned on a `build` context field; (c) one gateway per build. Leaning (b).
- **Replay.** "Test exact live response" must re-issue the captured tool calls to the Gateway
  under the current build, without a new model call.
- **Stage dependency.** Every click needs the network; keep the local path as a labelled fallback.
- **Model.** Maverick follows the injection reliably; confirm Strands tool-use with it, or pick a
  model that supports forced tool choice.
- **Where boto3 scripts go.** Keep them until Terraform parity is proven in a fresh account.

## New Terraform roots

`data` (DynamoDB tickets), `identity` (Cognito), `runtime` (code bucket, role, agent runtime),
`evaluations` (evaluators, online evaluation config, alarms), and an interceptor in `gateway`.
