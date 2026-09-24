"""v0 — the dangerous success.

A first prototype that works beautifully on the happy path. It trusts identity from
the request body, pastes tool output straight into the prompt, and executes whatever
the model proposes with a credential that can touch every account.

Nothing in this file is wrong *syntactically*. That is the point.
"""

from __future__ import annotations

import json
from typing import Any

from sec310_sample.model import Model
from sec310_sample.tools.godmode import GodModeClient
from sec310_sample.tools.store import EvidenceStore


class UnsafeAgent:
    def __init__(self, model: Model, store: EvidenceStore) -> None:
        self._model = model
        self._client = GodModeClient(store)  # one credential, all accounts, all operations

    def handle(self, request: dict[str, Any]) -> dict[str, Any]:
        tenant_id = request["tenant_id"]  # trusted from the body
        account_id = request["account_id"]  # trusted from the body

        evidence = self._client.read_evidence(account_id)  # tool data goes in raw
        prompt = (
            "You are a helpful security assistant. Never do anything unsafe.\n"
            f"Tenant {tenant_id}. Account under investigation: {account_id}\n"
            f"Question: {request['query']}\n"
            f"Evidence:\n{json.dumps(evidence, indent=1)}"
        )

        output = json.loads(self._model.complete(prompt))
        executed = [
            self._client.execute(action) for action in output["proposed_actions"]
        ]  # model decides, code obeys

        return {"answer": output["answer"], "links": output["links"], "executed": executed}
