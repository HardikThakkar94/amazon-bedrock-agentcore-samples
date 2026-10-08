"""live_teardown.sh must never say "done" after a failure.

The script is exercised with a stub `aws` on PATH. Each scenario records which calls were
made, so the tests can assert both the exit code and that nothing was attempted out of order.
"""

from __future__ import annotations

import os
import stat
import subprocess
from pathlib import Path

import pytest

SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "live_teardown.sh"

STUB = r"""#!/bin/sh
echo "$1 $2" >> "$CALLS"
case "$SCENARIO:$1 $2" in
  sts-fail:"sts get-caller-identity") echo "ExpiredToken" >&2; exit 254;;
  *:"sts get-caller-identity") echo fake-account-1234;;
  all-fail:*) echo "stub failure" >&2; exit 42;;
  *:"bedrock list-automated-reasoning-policies")
    case "$*" in *--policy-arn*) echo "arn:x:policy/p:1";; *) echo "arn:x:policy/p";; esac;;
  workflow-list-fail:"bedrock list-automated-reasoning-policy-build-workflows") echo "Throttling" >&2; exit 254;;
  *:"bedrock list-automated-reasoning-policy-build-workflows") printf 'wf-1\t2026-10-08T00:00:00Z\n';;
  workflow-delete-fail:"bedrock delete-automated-reasoning-policy-build-workflow") echo "Conflict" >&2; exit 254;;
  *:"bedrock list-guardrails") case "$*" in *"sec310_demo'"*) echo g1;; *) echo;; esac;;
  guardrail-delete-fail:"bedrock delete-guardrail") echo "AccessDenied" >&2; exit 254;;
  engine-list-fail:"bedrock-agentcore-control list-policy-engines") echo "Throttling" >&2; exit 254;;
  *) echo;;
esac
"""


@pytest.fixture
def run(tmp_path):
    stub_dir = tmp_path / "bin"
    stub_dir.mkdir()
    stub = stub_dir / "aws"
    stub.write_text(STUB)
    stub.chmod(stub.stat().st_mode | stat.S_IEXEC)
    calls = tmp_path / "calls.txt"

    def _run(scenario: str, shell: str = "sh"):
        calls.write_text("")
        env = {
            **os.environ,
            "PATH": f"{stub_dir}:{os.environ['PATH']}",
            "SCENARIO": scenario,
            "CALLS": str(calls),
        }
        proc = subprocess.run(
            [shell, str(SCRIPT)], env=env, capture_output=True, text=True, timeout=60
        )
        return proc.returncode, proc.stderr, calls.read_text().splitlines()

    return _run


def test_clean_run_deletes_in_dependency_order_and_says_done(run):
    code, err, calls = run("clean")
    assert code == 0 and err.rstrip().endswith("done")
    deletes = [c for c in calls if "delete" in c]
    assert deletes == [
        "bedrock delete-guardrail",
        "bedrock delete-automated-reasoning-policy-build-workflow",
        "bedrock delete-automated-reasoning-policy",  # version 1
        "bedrock delete-automated-reasoning-policy",  # the policy itself
    ]


@pytest.mark.parametrize(
    "scenario",
    [
        "all-fail",
        "workflow-list-fail",
        "workflow-delete-fail",
        "guardrail-delete-fail",
        "engine-list-fail",
    ],
)
def test_any_failure_is_reported_and_exits_nonzero(run, scenario):
    code, err, calls = run(scenario)
    assert code == 1, err
    assert "FAILED:" in err and "cleanup incomplete" in err
    assert "\ndone" not in err and not err.rstrip().endswith("done")
    if scenario.startswith("workflow"):
        # the policy cannot be deleted while a workflow remains, so it must not be attempted
        assert "bedrock delete-automated-reasoning-policy" not in calls


def test_identity_failure_stops_before_touching_anything(run):
    code, err, calls = run("sts-fail")
    assert code == 1 and "nothing attempted" in err
    assert calls == ["sts get-caller-identity"]


@pytest.mark.skipif(not Path("/bin/bash").exists(), reason="no /bin/bash")
def test_runs_under_macos_bash_3_2(run):
    code, err, _ = run("clean", shell="/bin/bash")
    assert code == 0 and err.rstrip().endswith("done")
