"""Evals matrix density layout: honest visual fixtures and the shipped console in real Chrome.

Presentation-only coverage. The fixtures under tests/fixtures/evals_density are synthetic
local snapshots shaped like /api/evals (NOT live release evidence); their DONE gates are
recomputed by the shared contract so the layout tests cannot invent a verdict.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tests"))
import evals_density_fixtures as fixtures  # noqa: E402

NAMES = [path.stem for path in sorted(fixtures.FIXTURE_DIR.glob("*.json"))]


def test_fixture_files_are_labelled_and_match_the_generator():
    assert set(NAMES) == set(fixtures.fixtures()), NAMES
    generated = fixtures.fixtures()
    for name in NAMES:
        payload = fixtures.load(name)
        assert "VISUAL FIXTURE" in payload["fixture_note"]
        assert "not live release evidence" in payload["fixture_note"]
        fixtures.verify(payload)
        assert payload == generated[name], (
            f"regenerate: python tests/evals_density_fixtures.py --write ({name})"
        )


def test_v0_failure_fixture_reproduces_the_live_failure_screenshot_state():
    """Hardik's second screenshot: V0 DONE/FAIL on the current .9 dataset, V1-V5 historical .4."""
    builds = fixtures.load("v0_fail_current_hist4")["builds"]
    v0 = builds["v0"]
    assert v0["dataset"] == fixtures.VERSION and v0["dataset_status"] == "current"
    assert v0["status"] == "DONE" and v0["gate"]["passed"] is False
    gate = v0["gate"]
    assert gate["safety"] == "FAIL"
    assert sum(r["passed"] for r in gate["cases"]) == 7 and sum(r["k"] for r in gate["cases"]) == 17
    assert gate["quality"] == {
        "helpfulness_mean": None,
        "scored": 0,
        "total": 3,
        "floor": 0.5,
        "passed": False,
    }
    assert (gate["controls"]["status"], gate["controls"]["passed"], gate["controls"]["total"]) == (
        "FAIL",
        0,
        17,
    )
    summary = {r["id"]: r for r in gate["cases"]}["benign_summary"]
    assert (summary["safety"], summary["passed"], summary["k"]) == ("PASS", 1, 1)
    assert (summary["control_family"], summary["control"], summary["control_passed"]) == (
        "guardrail",
        "FAIL",
        0,
    )
    assert summary["quality"] == {
        "status": "FAIL",
        "eligible": 0,
        "k": 1,
        "mean": None,
        "floor": 0.5,
        "reason": "successful guardrail screen not proven",
    }
    for build in ("v1", "v2", "v3", "v4", "v5"):
        record = builds[build]
        assert record["dataset"] == fixtures.HISTORICAL_VERSION
        assert record["dataset_status"] == "historical" and record["cases"]


def test_running_mixed_fixture_reproduces_the_first_screenshot_state():
    builds = fixtures.load("running_mixed")["builds"]
    assert builds["v0"]["status"] == "RUNNING" and builds["v0"]["progress"] == "7/17 runs"
    assert builds["v0"]["dataset_status"] == "current" and "cases" not in builds["v0"]
    travel = {r["id"]: r for r in builds["v4"]["gate"]["cases"]}["benign_note"]
    assert travel["control"] == "FAIL" and travel["quality"]["status"] == "FAIL"
    assert travel["quality"]["mean"] is None
    assert travel["quality"]["reason"] == "benign task withheld or stopped"
    assert all(builds[f"v{n}"]["dataset_status"] == "historical" for n in range(1, 6))


def test_console_markup_drops_hover_only_capsules():
    html = (ROOT / "web/index.html").read_text()
    assert "Hover cells for bounded per-sample provenance" not in html
    assert "cursor:help" not in html and 'class="evhead"' not in html
    assert (
        "Select a cell for its eligibility, floor, reason and bounded per-sample provenance" in html
    )
    # The release-gate badge text is one status word; counts and reasons live in the disclosure.
    assert 'class="c RUN">${esc(st.status)}</span>' in html
    assert (
        "<span class=\"c ${st.gate?.passed ? 'PASS' : 'FAIL'}\">${st.gate?.passed ? 'PASS' : 'FAIL'}</span>"
        in html
    )
    assert "gateReason(st)}</span>" not in html
    assert ".drawer.wide{" in html and ".drawer[data-from=evals] .body{" in html
    # Run-trace privacy fences are untouched by the presentation change.
    assert (
        "if(d.dataset.runTrace === '1') { drawerEpoch++; $('#drBody').replaceChildren(); $('#drTitle').textContent = ''; }"
        in html
    )
    assert (
        "function invalidateRunDrawer(){\n  const d = $('#drawer'); if(d.dataset.runTrace !== '1') return;"
        in html
    )


def test_evals_density_layout_in_chrome(tmp_path):
    python = os.environ.get("UI_BROWSER_PYTHON")
    if not python:
        pytest.skip("set UI_BROWSER_PYTHON to an installed Python with Playwright (no downloads)")
    shots = os.environ.get("UI_SCREENSHOTS", str(tmp_path))
    result = subprocess.run(
        [python, "tests/evals_density_browser.py"],
        cwd=ROOT,
        env={**os.environ, "UI_SCREENSHOTS": shots},
        capture_output=True,
        text=True,
        timeout=300,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    assert "PASS: evals density layout" in result.stdout
    produced = sorted(p.name for p in (Path(shots) / "evals-density").glob("*.png"))
    for scenario in fixtures.fixtures():
        for width, height in ((1920, 1080), (1440, 900), (1280, 800), (834, 900), (390, 844)):
            assert f"{scenario}-{width}x{height}.png" in produced, (scenario, width, height)
    assert "v0_fail_current_hist4-1440x900-detail-open.png" in produced
    assert "trace-drawer-after-evals-1440x900.png" in produced
    print(json.dumps({"screenshots": shots, "count": len(produced)}))
