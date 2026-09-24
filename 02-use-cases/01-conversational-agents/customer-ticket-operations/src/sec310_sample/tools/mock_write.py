"""Mutating tool client. Only ``update_rule`` exists here. There is no delete method to call."""

from __future__ import annotations

from typing import Any

from sec310_sample.credentials import CapabilityCredential
from sec310_sample.errors import AuthorizationError
from sec310_sample.schemas import Operation
from sec310_sample.tools.store import EvidenceStore


class WriteClient:
    def __init__(self, store: EvidenceStore, credential: CapabilityCredential) -> None:
        self._store = store
        self._cred = credential

    def update_rule(self, account_id: str, rule_id: str, change: dict[str, Any]) -> dict[str, Any]:
        if not self._cred.permits(Operation.UPDATE_RULE, account_id):
            raise AuthorizationError("write_capability_denied")
        return self._store.update_rule(account_id, rule_id, change)
