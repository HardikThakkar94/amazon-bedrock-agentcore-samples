"""Shared test fixtures. Everything is synthetic and in-memory."""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

import pytest

from sec310_sample.model import ScriptedModel
from sec310_sample.tools.store import FIXTURES, EvidenceStore


@pytest.fixture(autouse=True)
def isolate_demo_environment(monkeypatch, request):
    """Unit tests must also pass in a shell configured for rehearsal. Live integration tests
    explicitly opted in with SEC310_LIVE=1 retain their own configured service identifiers."""
    if (
        os.environ.get("SEC310_LIVE") == "1"
        and request.node.cls is not None
        and request.node.cls.__name__ == "TestLiveIntegration"
    ):
        return
    for name in list(os.environ):
        if name.startswith("SEC310_") and name != "SEC310_LIVE":
            monkeypatch.delenv(name)


def load_fixture(name: str) -> dict[str, Any]:
    return json.loads((FIXTURES / f"{name}.json").read_text())


@pytest.fixture
def store() -> EvidenceStore:
    return EvidenceStore.from_fixture()


@pytest.fixture
def poisoned_store() -> EvidenceStore:
    """Evidence store where one finding in acct-a carries an injected instruction."""
    store = EvidenceStore.from_fixture()
    fixture = load_fixture("indirect-injection")
    store.add_finding("acct-a", fixture["poisoned_finding"])
    return store


@pytest.fixture
def model() -> ScriptedModel:
    return ScriptedModel()


@pytest.fixture
def fixtures_dir() -> Path:
    return FIXTURES
