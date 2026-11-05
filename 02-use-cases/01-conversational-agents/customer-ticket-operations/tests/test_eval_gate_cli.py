"""Mock the k10 CLI's account boundary; do not start Lambda or read credentials."""

import importlib.util
import json
import sys
from pathlib import Path
from types import SimpleNamespace

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("sec310_eval_gate_cli", ROOT / "scripts/eval_gate.py")
cli = importlib.util.module_from_spec(spec)
spec.loader.exec_module(cli)


def setup(monkeypatch, incomplete=False):
    case_data = json.loads((ROOT / "evals/dataset-k10.json").read_text())
    calls = []
    monkeypatch.setattr(
        cli.boto3,
        "client",
        lambda service, **kw: SimpleNamespace(
            get_parameter=lambda Name: {"Parameter": {"Value": "fake-resource"}}
        ),
    )
    monkeypatch.setattr(
        cli.boto3,
        "resource",
        lambda *args, **kw: SimpleNamespace(Table=lambda _: SimpleNamespace()),
    )

    def run_one(lam, state, function, key, payload, timeout):
        calls.append((key, payload))
        case = next(c for c in case_data["cases"] if c["id"] == payload["case"])
        n = case["samples"] - int(incomplete and case["kind"] == "attack")
        scores = {"no_forbidden_effect": {"label": "PASS"}}
        if case["kind"] == "benign":
            scores["Builtin.Helpfulness"] = {"label": "PASS", "value": 0.9}
        samples = [{"scores": scores, "local": "PASS"} for _ in range(n)]
        return {
            "status": "DONE",
            "dataset": case_data["version"],
            "cases": [
                {
                    "id": case["id"],
                    "title": case["title"],
                    "kind": case["kind"],
                    "samples": samples,
                }
            ],
        }

    monkeypatch.setattr(cli, "run_one", run_one)
    monkeypatch.setattr(sys, "argv", ["eval_gate.py", "--build", "v5", "--dataset", "k10"])
    return calls


def test_k10_cli_completes_every_sample_and_reuses_strict_gate(monkeypatch):
    calls = setup(monkeypatch)
    assert cli.main() == 0
    assert len(calls) == 7
    assert all(key.endswith(payload["case"]) for key, payload in calls)
    assert all(payload["dataset"] == "k10" for _, payload in calls)


def test_k10_cli_rejects_missing_sample_without_a_green_gate(monkeypatch):
    calls = setup(monkeypatch, incomplete=True)
    assert cli.main() == 2
    assert len(calls) == 3  # two benign cases, then first attack is incomplete
