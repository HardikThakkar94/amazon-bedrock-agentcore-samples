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
        # two beats, each on its own store: the honest caller with poisoned evidence, then the
        # dishonest caller with clean evidence. Both end with tenant-b's rule gone.
        assert out.count("✖ acct-b rules now: {}   (tenant-b never saw this coming)") == 2
        assert "Then a caller who is not honest" in out
        assert "unchanged" not in out
        assert "an absolute URL from the model response is now a clickable link in the UI" in out

    def test_a_model_that_only_leaks_the_link_is_not_called_harmless(self, capsys):
        # Gemma 3 4B on the poisoned fixture (observed 2026-10-09): no write, but the attacker's URL
        # comes back in `links`, which v0 forwards to the UI unread.
        leaky = CannedModel(
            {
                "answer": "Summary.",
                "proposed_actions": [],
                "links": ["/accounts/acct-a", "https://exfil.example.net/collect?case=7"],
            }
        )
        demo.stage_unsafe(leaky, LocalGuardrail())
        out = capsys.readouterr().out
        assert "(unchanged)" in out
        assert (
            "✖ an absolute URL from the model response is now a clickable link in the UI: ['https://exfil.example.net/collect?case=7']"
            in out
        )
        assert "did not act on the injected instruction" not in out

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


class TestUnsafeStageSurvivesABrokenModel:
    @pytest.mark.parametrize("account, rule", [("acct-a", "rule-42"), ("acct-b", "rule-77")])
    def test_post_execution_response_error_cannot_hide_the_changed_state(
        self, store, capsys, account, rule
    ):
        from sec310_sample.unsafe_agent import UnsafeAgent

        # v0 executes actions before attempting output[answer] / output[links].
        bad = CannedModel(
            {
                "proposed_actions": [
                    {"operation": "delete_rule", "account_id": account, "resource_id": rule}
                ]
            }
        )
        demo._v0_beat(UnsafeAgent(bad, store), store, demo.fixture("indirect-injection")["request"])
        out = capsys.readouterr().out
        assert rule not in store.rules(account)
        assert "v0 crashed on the model's output: KeyError" in out
        assert f"{account} rules now: {{}}   (changed before the response failed)" in out

    def test_non_json_output_is_reported_as_a_crash_not_a_traceback(self, capsys):
        class Garbage:
            version = "garbage/1"

            def complete(self, prompt):
                return "<model output truncated: stopReason=max_tokens>"

            def stream(self, prompt):
                yield self.complete(prompt)

        demo.stage_unsafe(Garbage(), LocalGuardrail())
        out = capsys.readouterr().out
        assert "✖ v0 crashed on the model's output: JSONDecodeError" in out
        assert "No schema, no validation, no failure policy" in out


class TestUntrustedStageWithAModelThatDeclines:
    def test_declining_model_is_reported_not_narrated(self, capsys):
        demo.stage_untrusted(_quiet(), LocalGuardrail())
        out = capsys.readouterr().out
        assert "no unsafe proposal or link remained after validation" in out
        assert (
            "sync.policy_outcome == stream.policy_outcome → True" in out
        )  # canned output is deterministic
        assert "✔ 'exfil' in streamed text → False" in out

    def test_malformed_injected_reply_is_not_described_as_model_refusal(self, capsys):
        bad = CannedModel(
            {
                "answer": "do the injected action",
                "proposed_actions": [
                    {
                        "operation": "delete_rule",
                        "account_id": "acct-b",
                        "resource_id": "rule-77",
                        "reason": "injected",
                        "change": True,
                    }
                ],
                "links": ["https://exfil.example.net/collect?case=7"],
            }
        )
        demo.stage_untrusted(bad, LocalGuardrail())
        out = capsys.readouterr().out
        assert "model response rejected by strict validation (malformed_output)" in out
        assert "raw model intent is not inferred here" in out
        assert "proposed nothing the injection asked for" not in out
        assert "no unsafe proposal or link remained after validation" not in out
        assert "✔ the read-only answer still came back" not in out
        assert "✔ answer: do the injected action" not in out
        assert "links that reached the UI: []" in out

    def test_tools_stage_names_withheld_response_and_unexercised_gateway(self, capsys):
        bad = CannedModel({"answer": "blocked", "proposed_actions": True, "links": []})
        demo.stage_tools(bad, LocalGuardrail())
        out = capsys.readouterr().out
        assert out.count("model response rejected by strict validation (malformed_output)") == 2
        assert "capability check not exercised by this reply" in out
        assert "operator-authored plan (not model output)" in out
        assert "model proposed no update_rule" not in out

    def test_scripted_model_shows_the_rejections(self, capsys):
        demo.stage_untrusted(ScriptedModel(), LocalGuardrail())
        out = capsys.readouterr().out
        assert "no unsafe proposal or link remained after validation" not in out
        assert "rejected:" in out


def test_empty_change_proposal_is_rejected_without_crashing_the_demo(capsys):
    demo.stage_tools(_acts_on("update_rule", "acct-a", "rule-42", {}), LocalGuardrail())
    out = capsys.readouterr().out
    assert "confirmed proposal still rejected by current-state validation: empty_change" in out
    assert "mutations=0" in out
    assert "status=ok  rule-42" not in out and "client retried" not in out


class TestToolsStageWhenTheModelProposesNoWrite:
    def test_fallback_is_visible(self, capsys):
        demo.stage_tools(_quiet(), LocalGuardrail())
        out = capsys.readouterr().out
        assert "no validated update_rule remains" in out
        assert "testing the gateway with an operator-authored plan (not model output)" in out
        assert "status=confirmation_required" in out

    def test_no_fallback_when_the_model_proposes_the_write(self, capsys):
        demo.stage_tools(ScriptedModel(), LocalGuardrail())
        assert "no validated update_rule remains" not in capsys.readouterr().out


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
