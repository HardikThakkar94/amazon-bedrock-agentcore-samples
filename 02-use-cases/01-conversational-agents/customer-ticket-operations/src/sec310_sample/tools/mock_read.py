"""Read-only tool client. Carries a read capability and nothing else."""

from __future__ import annotations

from typing import Any

from sec310_sample.credentials import CapabilityCredential
from sec310_sample.errors import AuthorizationError
from sec310_sample.schemas import Operation
from sec310_sample.tools.store import EvidenceStore


class ReadClient:
    def __init__(self, store: EvidenceStore, credential: CapabilityCredential) -> None:
        self._store = store
        self._cred = credential

    def read_evidence(self, account_id: str) -> dict[str, Any]:
        if not self._cred.permits(Operation.READ_EVIDENCE, account_id):
            raise AuthorizationError("read_capability_denied")
        return {
            "account_id": account_id,
            "findings": self._store.findings(account_id),
            "rules": self._store.rules(account_id),
        }

    def rule(self, account_id: str, rule_id: str) -> dict[str, Any]:
        if not self._cred.permits(Operation.READ_EVIDENCE, account_id):
            raise AuthorizationError("read_capability_denied")
        return self._store.rule(account_id, rule_id)
