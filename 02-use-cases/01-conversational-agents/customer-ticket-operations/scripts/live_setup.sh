#!/bin/sh
# Create the AWS resources the `live` stage needs, in the current AWS CLI profile/region.
#
# Creates (all named sec310_demo*, all removed by live_teardown.sh):
#   - a Bedrock guardrail with the prompt-attack filter            -> SEC310_GUARDRAIL_ID
#   - an Automated Reasoning policy built from live/rule-change-policy.txt, versioned,
#     and a second guardrail with that policy attached              -> SEC310_AR_GUARDRAIL_ID
#
# Prints the `export` lines to paste before `python -m sec310_sample.demo live`.
# Needs: aws CLI v2, python3, credentials with Bedrock permissions. Takes a few minutes
# (the policy build is asynchronous).
set -eu

here=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
model_id=${SEC310_MODEL_ID:-global.anthropic.claude-haiku-4-5-20251001-v1:0}
profile_id=${SEC310_GUARDRAIL_PROFILE:-us.guardrail.v1:0}   # AR checks need a cross-Region guardrail profile

say() { printf '%s\n' "$*" >&2; }

say "account: $(aws sts get-caller-identity --query Account --output text | sed 's/^[0-9]\{8\}/****/')  region: ${AWS_REGION:-${AWS_DEFAULT_REGION:-$(aws configure get region)}}"

# -- prompt-attack guardrail ----------------------------------------------------------------
gid=$(aws bedrock list-guardrails --query "guardrails[?name=='sec310_demo'].id | [0]" --output text)
if [ "$gid" = "None" ] || [ -z "$gid" ]; then
  gid=$(aws bedrock create-guardrail --name sec310_demo \
    --description "SEC310 code talk live stage; throwaway" \
    --blocked-input-messaging "Blocked by guardrail." --blocked-outputs-messaging "Blocked by guardrail." \
    --content-policy-config '{"filtersConfig":[{"type":"PROMPT_ATTACK","inputStrength":"HIGH","outputStrength":"NONE"}]}' \
    --query guardrailId --output text)
  say "created guardrail sec310_demo ($gid)"
else
  say "guardrail sec310_demo exists ($gid)"
fi

# -- automated reasoning policy -------------------------------------------------------------
arn=$(aws bedrock list-automated-reasoning-policies --query "automatedReasoningPolicySummaries[?name=='sec310_demo_ar'].policyArn | [0]" --output text)
if [ "$arn" = "None" ] || [ -z "$arn" ]; then
  arn=$(aws bedrock create-automated-reasoning-policy --name sec310_demo_ar \
    --description "SEC310 live stage; built from rule-change-policy.txt; throwaway" --query policyArn --output text)
  say "created automated reasoning policy sec310_demo_ar"
  doc=$(base64 < "$here/live/rule-change-policy.txt" | tr -d '\n')
  wf=$(aws bedrock start-automated-reasoning-policy-build-workflow --policy-arn "$arn" \
    --build-workflow-type INGEST_CONTENT \
    --source-content "{\"workflowContent\":{\"documents\":[{\"document\":\"$doc\",\"documentContentType\":\"txt\",\"documentName\":\"rule-change-policy\",\"documentDescription\":\"An English-language policy. Write all variable names and descriptions in English (camelCase identifiers).\"}]}}" \
    --query buildWorkflowId --output text)
  say "building the policy from the document (workflow $wf) ..."
  status=BUILDING
  while [ "$status" = "BUILDING" ] || [ "$status" = "SCHEDULED" ] || [ "$status" = "TESTING" ]; do
    sleep 10
    status=$(aws bedrock get-automated-reasoning-policy-build-workflow --policy-arn "$arn" --build-workflow-id "$wf" --query status --output text)
  done
  [ "$status" = "COMPLETED" ] || { say "policy build ended $status"; exit 1; }
  # The build produces a proposed definition; it becomes the policy only when applied.
  tmp=$(mktemp)
  aws bedrock get-automated-reasoning-policy-build-workflow-result-assets --policy-arn "$arn" --build-workflow-id "$wf" \
    --asset-type POLICY_DEFINITION --query buildWorkflowAssets.policyDefinition --output json > "$tmp"
  aws bedrock update-automated-reasoning-policy --policy-arn "$arn" --policy-definition "file://$tmp" > /dev/null
  rm -f "$tmp"
  hash=$(aws bedrock get-automated-reasoning-policy --policy-arn "$arn" --query definitionHash --output text)
  varn=$(aws bedrock create-automated-reasoning-policy-version --policy-arn "$arn" --last-updated-definition-hash "$hash" --query policyArn --output text)
  say "policy version ${varn##*:} with $(aws bedrock export-automated-reasoning-policy-version --policy-arn "$varn" --query 'length(policyDefinition.rules)' --output text) rules"
else
  # versions list alongside the draft; take the highest numbered version
  varn=$(aws bedrock list-automated-reasoning-policies --policy-arn "$arn" --query 'automatedReasoningPolicySummaries[].policyArn' --output text \
    | tr '\t' '\n' | awk -F: '$NF ~ /^[0-9]+$/ {print $NF, $0}' | sort -n | tail -1 | cut -d' ' -f2)
  [ -n "$varn" ] || { say "sec310_demo_ar has no version; run live_teardown.sh and try again"; exit 1; }
  say "automated reasoning policy sec310_demo_ar exists (latest version ${varn##*:})"
fi

# -- guardrail with the AR policy attached --------------------------------------------------
ar_gid=$(aws bedrock list-guardrails --query "guardrails[?name=='sec310_demo_ar'].id | [0]" --output text)
if [ "$ar_gid" = "None" ] || [ -z "$ar_gid" ]; then
  ar_gid=$(aws bedrock create-guardrail --name sec310_demo_ar \
    --description "SEC310 live stage; Automated Reasoning policy attached; throwaway" \
    --blocked-input-messaging "Blocked." --blocked-outputs-messaging "Blocked." \
    --cross-region-config "{\"guardrailProfileIdentifier\":\"$profile_id\"}" \
    --automated-reasoning-policy-config "{\"policies\":[\"$varn\"],\"confidenceThreshold\":0.5}" \
    --query guardrailId --output text)
  say "created guardrail sec310_demo_ar ($ar_gid)"
else
  say "guardrail sec310_demo_ar exists ($ar_gid)"
fi

say ""
say "paste these, then: uv run python -m sec310_sample.demo live"
printf 'export SEC310_MODEL_ID=%s\n' "$model_id"
printf 'export SEC310_GUARDRAIL_ID=%s SEC310_GUARDRAIL_VERSION=DRAFT\n' "$gid"
printf 'export SEC310_AR_GUARDRAIL_ID=%s\n' "$ar_gid"
