"""Patch 5: telemetry describes decisions without carrying the data they were about."""

import pytest

from sec310_sample.decisions import Decision, GuardedSink
from sec310_sample.identity import RequestIdentity
from sec310_sample.telemetry import REDACTED, Tracer, Versions, hash_identifier

ALICE = RequestIdentity("tenant-a", "alice", frozenset({"acct-a"}))


def test_events_carry_versions_and_hashed_identifiers_only():
    tracer = Tracer(Versions(model_version="scripted-model/1"), key="k")

    tracer(
        Decision(
            "action",
            "action_gateway",
            "capability_absent",
            ALICE,
            "session-1",
            "delete_rule",
            "rule",
            3,
            detail="rule-42 in acct-a",
        )
    )

    event = tracer.export()[0]
    assert event["identity_hash"] == hash_identifier(ALICE.partition, "k")
    assert event["session_hash"] == hash_identifier("session-1", "k")
    assert event["model_version"] == "scripted-model/1" and event["prompt_version"].startswith(
        "prompt/"
    )
    assert event["target_class"] == "rule"
    assert "detail" not in event  # free text never reaches the indexed record
    tracer.assert_redacted(["alice", "tenant-a", "acct-a", "session-1", "rule-42"])


def test_identity_derived_values_are_scrubbed_from_indexed_tokens_at_runtime():
    """The mechanism, not just the test: a control that leaks an id into a token gets scrubbed."""
    tracer = Tracer(Versions(model_version="m"), key="k")

    tracer(
        Decision(
            "action",
            "action_gateway",
            "denied:acct-a",
            ALICE,
            "session-1",
            tool_name="read:alice",
            target_class="tenant-a",
        )
    )

    event = tracer.export()[0]
    assert event["outcome"] == f"denied:{REDACTED}"
    assert event["tool_name"] == f"read:{REDACTED}"
    assert event["target_class"] == REDACTED
    assert tracer.scrubbed == 3
    tracer.assert_redacted(["alice", "tenant-a", "acct-a", "session-1"])


def test_hash_is_keyed_and_stable_per_key():
    assert hash_identifier("tenant/tenant-a/principal/alice", "key-one") == hash_identifier(
        "tenant/tenant-a/principal/alice", "key-one"
    )
    assert hash_identifier("tenant/tenant-a/principal/alice", "key-one") != hash_identifier(
        "tenant/tenant-a/principal/alice", "key-two"
    )
    assert len(hash_identifier("x", "k")) == 16


def test_redaction_check_actually_fails_on_leaks():
    tracer = Tracer(Versions(model_version="leaky-model tenant-a"), key="k")
    tracer(Decision("model", "assistant", "ok"))

    with pytest.raises(AssertionError, match="tenant-a"):
        tracer.assert_redacted(["tenant-a"])


def test_outcome_counter_is_the_shape_of_a_dashboard():
    tracer = Tracer(Versions(model_version="m"), key="k")
    tracer(Decision("input", "guardrail", "none", ALICE, "s1"))
    tracer(Decision("input", "guardrail", "guardrail_intervened", ALICE, "s1"))
    tracer(Decision("input", "guardrail", "guardrail_intervened", ALICE, "s2"))

    assert tracer.outcomes()[("input", "guardrail", "guardrail_intervened")] == 2


def test_guarded_sink_counts_drops_and_does_not_double_wrap():
    def boom(decision):
        raise ValueError("sink down")

    guarded = GuardedSink(boom)
    guarded(Decision("model", "assistant", "ok"))
    assert guarded.dropped == 1

    rewrapped = GuardedSink(guarded)
    assert rewrapped.inner is boom  # components wrap once; a Tracer stays a Tracer
