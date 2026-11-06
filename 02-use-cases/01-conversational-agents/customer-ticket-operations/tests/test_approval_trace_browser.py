"""Shipped console approval trace after a successful new run and session rotation."""

from __future__ import annotations

import os
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]


@pytest.mark.parametrize(
    "delayed_events", (False, True), ids=("polled_events", "owner_proven_hydration")
)
def test_new_owned_approval_trace_survives_session_rotation_in_chrome(delayed_events):
    python = os.environ.get("UI_BROWSER_PYTHON")
    if not python:
        pytest.skip("set UI_BROWSER_PYTHON to installed offline Playwright")
    command = [python, "tests/approval_trace_browser.py"]
    if delayed_events:
        command.append("--late-events")
    result = subprocess.run(
        command,
        cwd=ROOT,
        env={**os.environ, "PYTHONDONTWRITEBYTECODE": "1"},
        capture_output=True,
        text=True,
        timeout=150,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    assert "one loopback approval POST" in result.stdout
    assert "new authorized run/events/Auto/Step" in result.stdout
