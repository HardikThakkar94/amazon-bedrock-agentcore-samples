#!/usr/bin/env bash
# Every tag must build and pass its own tests from a fresh checkout, with no borrowed environment.
# Usage: scripts/check_tags.sh          (from the repo root; needs uv and git; portable to bash 3.2)
set -euo pipefail

ORDER="v0-unsafe v1-identity v2-untrusted-data v3-bounded-tools v4-containment v5-telemetry"

expected_for() {
  case "$1" in
    v0-unsafe) echo 7 ;;
    v1-identity) echo 18 ;;
    v2-untrusted-data) echo 42 ;;
    v3-bounded-tools) echo 50 ;;
    v4-containment) echo 62 ;;
    v5-telemetry) echo 71 ;;
    *) echo "?" ;;
  esac
}

root=$(git rev-parse --show-toplevel)
scratch=$(mktemp -d "${TMPDIR:-/tmp}/sec310-tags.XXXXXX")
cleanup() {
  cd "$root"
  for t in $ORDER; do git worktree remove --force "$scratch/$t" 2>/dev/null || true; done
  git worktree prune
  rm -rf "$scratch"
}
trap cleanup EXIT

status=0
for tag in $ORDER; do
  wt="$scratch/$tag"                       # a fresh path per tag: uv's build cache is path-keyed
  git -C "$root" worktree add -q "$wt" "$tag"
  want=$(expected_for "$tag")
  if out=$(cd "$wt" && uv run --no-cache --quiet pytest -p no:cacheprovider 2>&1); then
    got=$( (printf '%s\n' "$out" | grep -Eo '[0-9]+ passed' | grep -Eo '[0-9]+' | tail -1) || true)
    if [ "$got" = "$want" ]; then
      printf '%-20s ok   %s passed\n' "$tag" "$got"
    else
      printf '%-20s FAIL expected %s passed, got %s\n' "$tag" "$want" "${got:-?}"; status=1
    fi
  else
    printf '%-20s FAIL build/test error:\n%s\n' "$tag" "$(printf '%s\n' "$out" | tail -5)"; status=1
  fi
done
exit $status
