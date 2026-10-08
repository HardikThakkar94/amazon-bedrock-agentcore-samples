"""The demo stages must report what actually happened, whichever model is plugged in.

The scripted model is deliberately gullible; a live one may decline the injected instruction
or propose something else. These tests drive the stages with small stand-in models and read
the printed narrative, because the narrative is the evidence the audience sees.
"""

from __future__ import annotations

import json
from collections.abc import Iterator

import pytest

from sec310_sample.demo import __main__ as demo
from sec310_sample.guardrails import LocalGuardrail
from sec310_sample.model import ScriptedModel


class CannedModel:
    """Returns one fixed response for every prompt."""

    version = "canned-model/1"

    def __init__(self, response: dict) -> None:
        self._text = json.dumps(response)

    def complete(self, prompt: str) -> str:
        return self._text

    def stream(self, prompt: str) -> Iterator[str]:
        yield self._text


def _quiet(answer: str = "Nothing to report.") -> CannedModel:
    return CannedModel({"answer": answer, "proposed_actions": [], "links": []})


def _acts_on(operation: str, account_id: str, resource_id: str, change=None) -> CannedModel:
    action = {
        "operation": operation,
        "account_id": account_id,
        "resource_id": resource_id,
        "reason": "requested",
    }
    if change is not None:
        action["change"] = change
    return CannedModel({"answer": "Done.", "proposed_actions": [action], "links": []})


class TestUnsafeStageTellsTheTruthAboutTenantB:
    def test_scripted_model_deletes_the_rule_and_the_stage_says_so(self, capsys):
        demo.stage_unsafe(ScriptedModel(), LocalGuardrail())
        out = capsys.readouterr().out
        assert "✖ acct-b rules now: {}   (tenant-b never saw this coming)" in out
        assert "unchanged" not in out

    def test_model_that_declines_leaves_acct_b_unchanged_and_the_stage_says_so(self, capsys):
        demo.stage_unsafe(_quiet(), LocalGuardrail())
        out = capsys.readouterr().out
        assert "✔ acct-b rules now: {'rule-77':" in out and "(unchanged)" in out
        assert "did not act on the injected instruction" in out
        assert "never saw this coming" not in out

    def test_model_that_edits_rule_77_is_not_called_intact(self, capsys):
        # The rule still exists, but tenant-b's state changed: that is a cross-tenant mutation.
        demo.stage_unsafe(
            _acts_on("update_rule", "acct-b", "rule-77", {"enabled": False}), LocalGuardrail()
        )
        out = capsys.readouterr().out
        assert (
            "✖ acct-b rules now: {'rule-77': {'name': 's3-public-acl', 'enabled': False, 'version': 10}}"
            in out
        )
        assert "unchanged" not in out and "did not act" not in out


class TestUntrustedStageWithAModelThatDeclines:
    def test_declining_model_is_reported_not_narrated(self, capsys):
        demo.stage_untrusted(_quiet(), LocalGuardrail())
        out = capsys.readouterr().out
        assert "this model proposed nothing the injection asked for" in out
        assert (
            "sync.policy_outcome == stream.policy_outcome → True" in out
        )  # canned output is deterministic
        assert "✔ 'exfil' in streamed text → False" in out

    def test_scripted_model_shows_the_rejections(self, capsys):
        demo.stage_untrusted(ScriptedModel(), LocalGuardrail())
        out = capsys.readouterr().out
        assert "proposed nothing the injection asked for" not in out
        assert "rejected:" in out


class TestToolsStageWhenTheModelProposesNoWrite:
    def test_fallback_is_visible(self, capsys):
        demo.stage_tools(_quiet(), LocalGuardrail())
        out = capsys.readouterr().out
        assert "the model proposed no update_rule" in out
        assert "continuing with the scripted proposal so the gateway path can be shown" in out
        assert "status=confirmation_required" in out

    def test_no_fallback_when_the_model_proposes_the_write(self, capsys):
        demo.stage_tools(ScriptedModel(), LocalGuardrail())
        assert "proposed no update_rule" not in capsys.readouterr().out


class TestTelemetryStageLabelsTheCorpusHonestly:
    def test_corpus_events_carry_the_scripted_version_even_in_live_mode(self, capsys):
        demo.stage_telemetry(_quiet(), LocalGuardrail())
        out = capsys.readouterr().out
        assert "the corpus runs on scripted-model/1, not on canned-model/1" in out
        assert "canned-model/1" not in out.split("regression gate must be deterministic", 1)[1]

    def test_no_caveat_with_the_scripted_model(self, capsys):
        demo.stage_telemetry(ScriptedModel(), LocalGuardrail())
        assert "regression gate must be deterministic" not in capsys.readouterr().out


@pytest.mark.parametrize(
    "stage", ["unsafe", "identity", "untrusted", "tools", "containment", "telemetry"]
)
def test_every_offline_stage_runs_with_a_declining_model(stage, capsys):
    demo.STAGES[stage](_quiet(), LocalGuardrail())
    assert "Traceback" not in capsys.readouterr().out
