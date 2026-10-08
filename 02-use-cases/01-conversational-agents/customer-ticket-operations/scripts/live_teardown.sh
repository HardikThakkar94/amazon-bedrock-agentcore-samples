#!/bin/sh
# Remove everything live_setup.sh created in the current AWS CLI profile/region, and any
# throwaway policy engine the `live` stage may have left behind (its name starts with
# sec310_demo). Nothing else is touched.
#
# Every listing and every deletion is checked. If anything could not be enumerated or
# removed, that is printed and the script exits 1: an incomplete cleanup must not say "done".
set -u

failed=0
say() { printf '%s\n' "$*" >&2; }
fail() { say "FAILED: $*"; failed=1; }

# run an aws query and print its output; on error, report and return non-zero. Runs inside
# $(...), so the CALLER must record the failure: `x=$(query ...) || { failed=1; continue; }`
query() {
  out=$(aws "$@" 2>&1) || { say "FAILED: aws $1 $2: $out"; return 1; }
  printf '%s\n' "$out"
}

account=$(query sts get-caller-identity --query Account --output text) || { say "cannot determine the caller identity; nothing attempted"; exit 1; }
say "account: $(printf '%s' "$account" | sed 's/^[0-9]\{8\}/****/')"

# -- guardrails ---------------------------------------------------------------------------
for name in sec310_demo sec310_demo_ar; do
  ids=$(query bedrock list-guardrails --query "guardrails[?name=='$name'].id" --output text) || { failed=1; continue; }
  for gid in $ids; do
    if aws bedrock delete-guardrail --guardrail-identifier "$gid"; then say "deleted guardrail $name ($gid)"; else fail "delete guardrail $name ($gid)"; fi
  done
done

# -- automated reasoning policy: build workflows, then versions, then the policy -----------
arns=$(query bedrock list-automated-reasoning-policies --query "automatedReasoningPolicySummaries[?name=='sec310_demo_ar'].policyArn" --output text) || { failed=1; arns=""; }
for arn in $arns; do
  workflows=$(query bedrock list-automated-reasoning-policy-build-workflows --policy-arn "$arn" \
    --query 'automatedReasoningPolicyBuildWorkflowSummaries[].[buildWorkflowId, updatedAt]' --output text) || { failed=1; continue; }
  while read -r wf updated; do
    [ -n "$wf" ] || continue
    if aws bedrock delete-automated-reasoning-policy-build-workflow --policy-arn "$arn" --build-workflow-id "$wf" --last-updated-at "$updated"; then
      say "deleted build workflow $wf"
    else
      fail "delete build workflow $wf"
    fi
  done <<EOF
$workflows
EOF
  [ "$failed" -eq 0 ] || continue   # the policy cannot go while a workflow remains
  versions=$(query bedrock list-automated-reasoning-policies --policy-arn "$arn" --query 'automatedReasoningPolicySummaries[].policyArn' --output text) || { failed=1; continue; }
  for varn in $versions; do
    case "${varn##*:}" in
      [0-9]*) if aws bedrock delete-automated-reasoning-policy --policy-arn "$varn"; then say "deleted policy version ${varn##*:}"; else fail "delete policy version ${varn##*:}"; fi ;;
    esac
  done
  if aws bedrock delete-automated-reasoning-policy --policy-arn "$arn"; then say "deleted automated reasoning policy sec310_demo_ar"; else fail "delete automated reasoning policy sec310_demo_ar"; fi
done

# -- throwaway policy engines the stage may have left behind ---------------------------------
engines=$(query bedrock-agentcore-control list-policy-engines --query "policyEngines[?starts_with(name, 'sec310_demo')].policyEngineId" --output text) || { failed=1; engines=""; }
for eng in $engines; do
  pids=$(query bedrock-agentcore-control list-policies --policy-engine-id "$eng" --query 'policies[].policyId' --output text) || { failed=1; continue; }
  for pid in $pids; do
    if aws bedrock-agentcore-control delete-policy --policy-engine-id "$eng" --policy-id "$pid" > /dev/null \
       && aws bedrock-agentcore-control wait policy-deleted --policy-engine-id "$eng" --policy-id "$pid"; then
      say "deleted policy $pid"
    else
      fail "delete policy $pid on engine $eng"
    fi
  done
  if aws bedrock-agentcore-control delete-policy-engine --policy-engine-id "$eng" > /dev/null; then say "deleted policy engine $eng"; else fail "delete policy engine $eng"; fi
done

if [ "$failed" -ne 0 ]; then
  say "cleanup incomplete: see FAILED lines above"
  exit 1
fi
say "done"
