"""Fail tests on *attempted* AWS SDK egress, including errors swallowed by telemetry.

Installed before test modules import boto3/Runtime entrypoints. Browser loopback fixtures
use their own explicit route guard; this guard covers botocore transport, not local HTTP.
"""

from __future__ import annotations

import os

# Avoid credential-chain metadata, profiles and any ambient AWS identity before module import.
os.environ["AWS_EC2_METADATA_DISABLED"] = "true"
os.environ.pop("AWS_PROFILE", None)
os.environ["AWS_ACCESS_KEY_ID"] = "offline-only"
os.environ["AWS_SECRET_ACCESS_KEY"] = "offline-only"
os.environ["AWS_DEFAULT_REGION"] = "us-east-1"

import botocore.client  # noqa: E402
import pytest  # noqa: E402

ATTEMPTED_AWS: list[str] = []
TOTAL_AWS_ATTEMPTS = 0


def forbid_sdk_egress(self, operation_name, api_params):
    global TOTAL_AWS_ATTEMPTS
    service = self.meta.service_model.service_name
    TOTAL_AWS_ATTEMPTS += 1
    ATTEMPTED_AWS.append(f"{service}.{operation_name}")
    raise AssertionError("AWS SDK egress attempted in offline tests")


# Instrument the SDK itself, not a mock that telemetry might silently swallow. Patching at
# import time also covers module-level boto3 resources created before pytest fixtures run.
botocore.client.BaseClient._make_api_call = forbid_sdk_egress


@pytest.fixture(autouse=True)
def no_attempted_aws_egress():
    assert not ATTEMPTED_AWS, "AWS egress attempted before test fixture admission"
    yield
    attempts = list(ATTEMPTED_AWS)
    ATTEMPTED_AWS.clear()
    assert not attempts, f"AWS SDK egress attempted (possibly swallowed): {attempts}"


def pytest_terminal_summary(terminalreporter):
    terminalreporter.write_line(
        f"Offline AWS SDK egress guard: {TOTAL_AWS_ATTEMPTS} attempted operations"
    )
