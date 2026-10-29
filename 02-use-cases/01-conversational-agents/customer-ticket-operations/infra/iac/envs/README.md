# Environments

One `.tfvars` + one `.tfbackend` per environment. Roots consume both via
`-var-file` and `-backend-config` flags (wired in the root `Makefile`).

## A new burner account

1. Update `account_id` in `burner.tfvars` and the account in the `bucket` name in `burner.tfbackend`.
2. Bootstrap the state backend: `make bootstrap PROFILE=<burner-profile>`
3. Deploy: `make deploy-all PROFILE=<burner-profile>`

## Reuse an existing Bedrock invocation-log destination (opt in)

The observability root normally provisions its own CloudWatch log group, IAM role/policy,
propagation wait, and **account/Region-wide** Bedrock invocation-logging configuration.
For a new isolated deployment in an account that already has model invocation logging,
set `existing_invocation_log_group` **only on the observability root** in a private
Terraform input file outside the repository. Example values (not real identifiers):

```hcl
# /private/path/observability-reuse.tfvars (operator-private, outside version control)
existing_invocation_log_group = "/aws/bedrock/example_existing_invocations"
```

For direct root commands, use the normal environment var-file first and then the private
file, e.g. from `infra/iac/roots/foundation/observability`:

```sh
terraform plan -var-file="../../../envs/burner.tfvars" -var-file="/private/path/observability-reuse.tfvars"
```

Supply `TF_VAR_account_id` through the operator's private environment; account IDs,
profiles, credentials, real log-group names and secrets stay in operator-private inputs
outside tracked files.
For `make plan-observability`/`deploy-observability`, `TFVARS` is a single path, so
use an **external combined** file with all environment variables plus the reuse input
rather than editing tracked `burner.tfvars`. Set a distinct `name_prefix` there for
all new resources and use a separate backend state namespace. Other roots must receive
the same project, environment, account, region and distinct prefix (without this optional
observability-only variable). Inspect the plan before any apply.

Reuse creates only the new environment's
`/<project>/<environment>/observability/invocation_log_group` SSM pointer and the
approved Transaction Search resources (CloudWatchLogs X-Ray destination and Default
100% indexing). It does **not** adopt, update, or verify the existing group, Bedrock
logging configuration, or IAM role/policy; an operator must independently check that
logging really targets that group before deployment. All references in the app root
continue to read the same SSM path. Transaction Search is account/Region-wide and
must be separately approved. Reuse references the current destination without changing
it; `scripts/live_logging.py up/down` instead changes account-wide logging.

The `moved` blocks retain default-mode addresses when upgrading an existing *default*
observability state. **Switching a populated default state into reuse mode would plan
deletion of its previously owned invocation resources, including the account-wide
configuration.** Reuse is scoped to a fresh isolated state. If migration of a
populated state is ever required, arrange explicit operator-controlled state detachment
and inspect a no-delete plan first. The offline mock plans cover clean-state behavior,
not account or populated-state verification.

## State layout

One S3 object per root:
    s3://sec310-<env>-tf-state-<account>-<region>/<env>/<root-relative-path>/terraform.tfstate
