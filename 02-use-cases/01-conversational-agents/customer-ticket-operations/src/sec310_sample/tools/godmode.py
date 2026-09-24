"""The v0 tool client: one wide credential, every operation, every account.

This is what most first prototypes look like. It exists so the cold open can show a
model-chosen action landing in the wrong tenant with nothing in the way.
"""

from __future__ import annotations

from typing import Any

from sec310_sample.tools.store import EvidenceStore


class GodModeClient:
    def __init__(self, store: EvidenceStore) -> None:
        self._store = store

    def read_evidence(self, account_id: str) -> dict[str, Any]:
        return {
            "account_id": account_id,
            "findings": self._store.findings(account_id),
            "rules": self._store.rules(account_id),
        }

    def execute(self, action: dict[str, Any]) -> dict[str, Any]:
        """Run whatever the model asked for. No policy, no confirmation, no audit."""
        op = action.get("operation")
        account_id = action.get("account_id", "")
        resource_id = action.get("resource_id", "")
        if op == "read_evidence":
            return {"operation": op, "account_id": account_id, "status": "ok"}
        if op == "update_rule":
            self._store.update_rule(
                account_id, resource_id, action.get("change") or {"enabled": True}
            )
            return {
                "operation": op,
                "account_id": account_id,
                "resource_id": resource_id,
                "status": "executed",
            }
        if op == "delete_rule":
            self._store.delete_rule(account_id, resource_id)
            return {
                "operation": op,
                "account_id": account_id,
                "resource_id": resource_id,
                "status": "executed",
            }
        return {"operation": op, "status": "unknown_operation"}
