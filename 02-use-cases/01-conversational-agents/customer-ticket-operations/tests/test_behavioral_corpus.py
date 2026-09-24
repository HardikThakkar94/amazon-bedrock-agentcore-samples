"""Patch 5: the corpus is the release gate. Every expectation is a stable token."""

from sec310_sample.evaluation import run_corpus, summarize
from sec310_sample.model import ScriptedModel
from sec310_sample.telemetry import Tracer, Versions


def test_every_corpus_case_matches_its_expectation():
    results = run_corpus()

    failures = [(r.id, r.expected, r.actual) for r in results if not r.passed]
    assert failures == []
    assert len(results) >= 12


def test_summary_reports_by_category():
    summary = summarize(run_corpus())

    assert set(summary) == {"task", "security", "service"}
    assert all(bucket["failed"] == 0 for bucket in summary.values())


def test_corpus_run_leaves_no_raw_identifiers_in_telemetry():
    tracer = Tracer(Versions(model_version=ScriptedModel.version), key="test-key")

    run_corpus(sink=tracer)

    assert len(tracer.events) > 10
    tracer.assert_redacted(
        [
            "alice",
            "bob",
            "tenant-a",
            "tenant-b",
            "acct-a",
            "acct-b",
            "session-1",
            "rule-42",
            "rule-77",
            "exfil",
        ]
    )
