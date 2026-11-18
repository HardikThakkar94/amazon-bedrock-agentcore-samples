# Customer Ticket Operations

A support-ticket agent built with Amazon Bedrock AgentCore. Customers submit tickets through a portal; operators review them, run the agent and approve ticket closures.

The sample uses Amazon Cognito, AgentCore Runtime and Gateway, Amazon Bedrock Guardrails, AgentCore Policy, AWS Lambda, Amazon DynamoDB and Amazon CloudWatch. The console compares six stages:

| Stage | Control added |
|---|---|
| V0 Unsafe | None: model output executes |
| V1 Guardrails | Ticket text screened for prompt attacks |
| V2 Identity | Tool access fenced to the caller's tenant |
| V3 Policy | Human approval before a ticket is closed |
| V4 Contain | Write cap and a circuit breaker |
| V5 Evidence | Release gated on passing evaluations |

> Use a dedicated AWS sandbox account and synthetic tickets. This is sample code and is not intended for production. Deployment and evaluations incur AWS charges.

> The deploy changes account-wide settings in `us-east-1`. It replaces the Amazon Bedrock model invocation logging configuration, so prompts and responses for every Bedrock call in the account are logged for 3 days, and it turns on CloudWatch Transaction Search with 100% span indexing. Teardown removes the logging configuration. Do not deploy into an account that other workloads share. To keep an existing logging destination, see [infra/iac/envs/README.md](infra/iac/envs/README.md).

## Get started

Prerequisites:

- A git clone of this repository (a ZIP download will not build).
- [uv](https://docs.astral.sh/uv/) (it installs Python 3.12+), AWS CLI v2, Terraform 1.10+, Git, Make and Zip. Node.js 20+ is needed only for `make test`.
- A named AWS CLI profile with `AdministratorAccess` in a sandbox account. Credentials from environment variables are not used; create a profile with `aws configure sso` or `aws configure --profile my-dev`.
- The sample deploys to `us-east-1` only.
- Amazon Bedrock model access for Meta Llama 4 Maverick (the agent) and Anthropic Claude Haiku 4.5 (the evaluation judge). Both run through `us.` inference profiles, which route to `us-east-1`, `us-east-2` and `us-west-2`.

1. Deploy the sample (run from this folder):

```bash
uv sync --extra aws
unset AWS_BEARER_TOKEN_BEDROCK   # a Bedrock API key in your shell would override the profile
aws sts get-caller-identity --profile my-dev --region us-east-1
make deploy-all PROFILE=my-dev REGION=us-east-1
make creds PROFILE=my-dev REGION=us-east-1
```

A deploy takes 20 to 35 minutes and prints `Demo URL: https://<id>.cloudfront.net` near the end.

2. `make creds` prints the demo URL and a password for each user to your terminal. The passwords are generated at deploy time and stored in AWS Secrets Manager. Open the URL and sign in as `presenter`. The gear menu switches between the two operators (alice and bob) and the Ticket Portal (carol). Deployment settings are in [infra/iac/envs/demo.tfvars](infra/iac/envs/demo.tfvars).
3. Submit a ticket from the portal, then choose **Run agent** and use the stage buttons (V0 to V5) to compare behavior.
4. At V3 and later, choose **Ask the agent to close** on an open ticket, run the agent, then **Approve** or **Reject** the request that appears.
5. **Evals** shows per-stage results and can start an evaluation suite.

## Test and clean up

```bash
make test
make eval PROFILE=my-dev REGION=us-east-1 BUILD=v5
make destroy-all PROFILE=my-dev REGION=us-east-1
```

`make eval` runs the evaluation suite for one stage. It takes 10 to 15 minutes, resets the demo, and exits non-zero when the release gate fails, which is expected for V0 to V3.

If an agent run ends in an error, the console shows **Recovery required** and blocks further runs, approvals and resets, because it cannot tell whether the agent is still working. `make recover` shows the lock and releases it once the run's time limit has passed; before that, it tells you how long to wait. Add `FORCE=1` to release it immediately when you know the run has stopped. A lock held by an evaluation suite is released only with `FORCE=1`. Then choose **Reset demo** in the gear menu.

```bash
make recover PROFILE=my-dev REGION=us-east-1
```

If a deploy failed partway, run `make -k destroy-all PROFILE=my-dev REGION=us-east-1` so that teardown continues past the parts that were never created.

Teardown keeps the Terraform state backend, which continues to incur a small cost. `make bootstrap-destroy PROFILE=my-dev REGION=us-east-1` removes the bootstrap stack but retains its versioned S3 state bucket. Empty and delete that bucket (`sec310-demo-tf-state-<account>-us-east-1`) before deploying again.

## License

[MIT-0](LICENSE).
