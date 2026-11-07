# Customer Ticket Operations

A support-ticket agent built with Amazon Bedrock AgentCore. Customers submit tickets through a portal; operators review them, run the agent and approve ticket closures.

The sample uses Cognito, AgentCore Runtime and Gateway, Bedrock Guardrails, AgentCore Policy, Lambda, DynamoDB and CloudWatch. The console compares six stages:

| Stage | Control added |
|---|---|
| V0 Unsafe | None: model output executes |
| V1 Guardrails | Ticket text screened for prompt attacks |
| V2 Identity | Tool access fenced to the caller's tenant |
| V3 Policy | Human approval before a ticket is closed |
| V4 Contain | Write cap and a circuit breaker |
| V5 Evidence | Release gated on passing evaluations |

> Use a dedicated AWS sandbox and synthetic tickets. This is sample code, not a production-ready application. Deployment and evaluations incur AWS charges; evaluation suites reset the demo.

## Get started

Prerequisites: Python 3.12+, [uv](https://docs.astral.sh/uv/), AWS CLI, Terraform 1.10+, Git, Make and Zip. Configure a sandbox AWS profile with Bedrock/AgentCore access in `us-east-1` and infrastructure-provisioning permissions, including IAM/PassRole and CloudFormation.

1. Deploy the sample (run from this folder):

```bash
uv sync --extra aws
unset AWS_BEARER_TOKEN_BEDROCK
aws sts get-caller-identity --profile my-dev --region us-east-1
make deploy-all PROFILE=my-dev REGION=us-east-1 AUTO_APPROVE=
make creds PROFILE=my-dev REGION=us-east-1
```

2. Open the printed demo URL and sign in as `presenter`. The gear menu switches between operators and the customer portal. Deployment settings are in [infra/iac/envs/burner.tfvars](infra/iac/envs/burner.tfvars).
3. Submit a synthetic ticket from the portal, then use **Run agent** and the stage buttons to compare behavior. At V3 and later, **Ask the agent to close** an open seed ticket, run the agent, then **Approve** or **Reject** the pending card. **Evals** shows per-stage results and can start a suite after confirmation.

## Test and clean up

```bash
uv pip install -r src/sec310_agent/requirements.txt
make test
make eval PROFILE=my-dev REGION=us-east-1 BUILD=v5
make destroy-all PROFILE=my-dev REGION=us-east-1 AUTO_APPROVE=
```

Teardown retains the Terraform-state backend and its costs. `make bootstrap-destroy PROFILE=my-dev REGION=us-east-1` removes the bootstrap stack; its versioned S3 state bucket is retained separately.

## License

[MIT-0](LICENSE).
