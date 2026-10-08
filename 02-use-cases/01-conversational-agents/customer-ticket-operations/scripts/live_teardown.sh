#!/bin/sh
# Remove everything live_setup.sh created in the current AWS CLI profile/region, and any
# throwaway policy engine the `live` stage may have left behind (its name starts with
# sec310_demo). Nothing else is touched.
set -eu

say() { printf '%s\n' "$*" >&2; }

say "account: $(aws sts get-caller-identity --query Account --output text | sed 's/^[0-9]\{8\}/****/')"

for name in sec310_demo sec310_demo_ar; do
  for gid in $(aws bedrock list-guardrails --query "guardrails[?name=='$name'].id" --output text); do
    aws bedrock delete-guardrail --guardrail-identifier "$gid" && say "deleted guardrail $name ($gid)"
  done
done

for arn in $(aws bedrock list-automated-reasoning-policies --query "automatedReasoningPolicySummaries[?name=='sec310_demo_ar'].policyArn" --output text); do
  # build workflows must go before the policy; the delete call needs each one's last update time
  aws bedrock list-automated-reasoning-policy-build-workflows --policy-arn "$arn" \
    --query 'automatedReasoningPolicyBuildWorkflowSummaries[].[buildWorkflowId, updatedAt]' --output text \
  | while read -r wf updated; do
      [ -n "$wf" ] || continue
      aws bedrock delete-automated-reasoning-policy-build-workflow --policy-arn "$arn" --build-workflow-id "$wf" --last-updated-at "$updated" \
        && say "deleted build workflow $wf"
    done
  for varn in $(aws bedrock list-automated-reasoning-policies --policy-arn "$arn" --query 'automatedReasoningPolicySummaries[].policyArn' --output text); do
    case "${varn##*:}" in [0-9]*) aws bedrock delete-automated-reasoning-policy --policy-arn "$varn" && say "deleted policy version ${varn##*:}";; esac
  done
  aws bedrock delete-automated-reasoning-policy --policy-arn "$arn" && say "deleted automated reasoning policy sec310_demo_ar"
done

for eng in $(aws bedrock-agentcore-control list-policy-engines --query "policyEngines[?starts_with(name, 'sec310_demo')].policyEngineId" --output text); do
  for pid in $(aws bedrock-agentcore-control list-policies --policy-engine-id "$eng" --query 'policies[].policyId' --output text); do
    aws bedrock-agentcore-control delete-policy --policy-engine-id "$eng" --policy-id "$pid" > /dev/null && say "deleted policy $pid"
    aws bedrock-agentcore-control wait policy-deleted --policy-engine-id "$eng" --policy-id "$pid"
  done
  aws bedrock-agentcore-control delete-policy-engine --policy-engine-id "$eng" > /dev/null && say "deleted policy engine $eng"
done
say "done"
