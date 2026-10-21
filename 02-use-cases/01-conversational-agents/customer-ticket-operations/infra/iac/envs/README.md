# Environments

One `.tfvars` + one `.tfbackend` per environment. Roots consume both via
`-var-file` and `-backend-config` flags (wired in the root `Makefile`).

## A new burner account

1. Update `account_id` in `burner.tfvars` and the account in the `bucket` name in `burner.tfbackend`.
2. Bootstrap the state backend: `make bootstrap PROFILE=<burner-profile>`
3. Deploy: `make deploy-all PROFILE=<burner-profile>`

## State layout

One S3 object per root:
    s3://sec310-<env>-tf-state-<account>-<region>/<env>/<root-relative-path>/terraform.tfstate
