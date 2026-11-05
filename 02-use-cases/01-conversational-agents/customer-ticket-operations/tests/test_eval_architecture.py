"""Presentation-only contract and the actual shipped script in a real browser."""

import os
import shutil
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]


def test_console_script_syntax(tmp_path):
    node = shutil.which("node")
    if not node:
        pytest.skip("node is needed to syntax-check the shipped script")
    html = (ROOT / "web/index.html").read_text()
    assert 'id="codeBtn"' not in html
    assert "$('#codeBtn')" not in html
    assert "api('/api/code')" in html  # The underlying read-only code view remains available.
    script = tmp_path / "console.js"
    script.write_text(html.split("<script>")[1].split("</script>")[0])
    subprocess.run([node, "--check", str(script)], check=True, cwd=ROOT)


def test_shipped_console_in_chrome(tmp_path):
    python = os.environ.get("UI_BROWSER_PYTHON")
    if not python:
        pytest.skip("set UI_BROWSER_PYTHON to an installed Python with Playwright (no downloads)")
    result = subprocess.run(
        [python, "tests/eval_architecture_browser.py"],
        cwd=ROOT,
        env={**os.environ, "UI_SCREENSHOTS": os.environ.get("UI_SCREENSHOTS", str(tmp_path))},
        capture_output=True,
        text=True,
        timeout=180,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    assert "PASS: shipped full-script boot" in result.stdout
