"""Patch 2: the streaming adapter must reach the same policy outcome as the synchronous one."""

import pytest

from sec310_sample.assistant import AssistantResult
from sec310_sample.identity import RequestIdentity
from tests.test_untrusted_data import make_assistant, raw_from

ALICE = RequestIdentity("tenant-a", "alice", frozenset({"acct-a"}), frozenset({"analyst"}))


@pytest.mark.parametrize("fixture", ["normal-evidence", "direct-injection", "indirect-injection"])
def test_sync_and_stream_agree_on_every_fixture(poisoned_store, model, fixture):
    sync_result = make_assistant(poisoned_store, model).handle_sync(raw_from(fixture), ALICE)

    events = list(make_assistant(poisoned_store, model).handle_stream(raw_from(fixture), ALICE))
    chunks, stream_result = events[:-1], events[-1]

    assert isinstance(stream_result, AssistantResult)
    assert stream_result.policy_outcome == sync_result.policy_outcome
    assert "".join(chunks) == stream_result.answer  # only validated text was ever streamed


def test_stream_never_emits_rejected_links(poisoned_store, model):
    events = list(
        make_assistant(poisoned_store, model).handle_stream(raw_from("indirect-injection"), ALICE)
    )
    streamed = "".join(e for e in events if isinstance(e, str))

    assert "exfil.example.net" not in streamed
