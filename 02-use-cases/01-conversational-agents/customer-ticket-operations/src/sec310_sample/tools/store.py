"""In-memory stand-in for the systems an investigation agent reads from and writes to."""

from __future__ import annotations

import copy
import json
from pathlib import Path
from typing import Any

FIXTURES = Path(__file__).resolve().parents[3] / "fixtures"


class EvidenceStore:
    """Findings and detection rules for a handful of synthetic accounts.

    Mutations are recorded in ``mutation_log`` so demos and tests can prove what
    actually changed, independent of what the agent *claims* happened.
    """

    def __init__(self, data: dict[str, Any]) -> None:
        self._accounts: dict[str, dict[str, Any]] = copy.deepcopy(data["accounts"])
        self.tenants: dict[str, list[str]] = copy.deepcopy(data["tenants"])
        self.mutation_log: list[dict[str, Any]] = []

    @classmethod
    def from_fixture(cls, name: str = "evidence-store.json") -> EvidenceStore:
        return cls(json.loads((FIXTURES / name).read_text()))

    # -- reads -----------------------------------------------------------------
    def accounts(self) -> list[str]:
        return sorted(self._accounts)

    def findings(self, account_id: str) -> list[dict[str, Any]]:
        return copy.deepcopy(self._account(account_id)["findings"])

    def rules(self, account_id: str) -> dict[str, dict[str, Any]]:
        return copy.deepcopy(self._account(account_id)["rules"])

    def rule(self, account_id: str, rule_id: str) -> dict[str, Any]:
        rules = self._account(account_id)["rules"]
        if rule_id not in rules:
            raise KeyError(f"unknown rule {rule_id!r} in {account_id!r}")
        return copy.deepcopy(rules[rule_id])

    # -- writes (the store itself has no opinion about who may call these) ------
    def add_finding(self, account_id: str, finding: dict[str, Any]) -> None:
        self._account(account_id)["findings"].append(copy.deepcopy(finding))

    def update_rule(self, account_id: str, rule_id: str, change: dict[str, Any]) -> dict[str, Any]:
        rules = self._account(account_id)["rules"]
        if rule_id not in rules:
            raise KeyError(f"unknown rule {rule_id!r} in {account_id!r}")
        rules[rule_id].update(change)
        rules[rule_id]["version"] += 1
        self.mutation_log.append(
            {"op": "update_rule", "account_id": account_id, "rule_id": rule_id, "change": change}
        )
        return copy.deepcopy(rules[rule_id])

    def delete_rule(self, account_id: str, rule_id: str) -> None:
        rules = self._account(account_id)["rules"]
        if rule_id not in rules:
            raise KeyError(f"unknown rule {rule_id!r} in {account_id!r}")
        del rules[rule_id]
        self.mutation_log.append(
            {"op": "delete_rule", "account_id": account_id, "rule_id": rule_id}
        )

    def _account(self, account_id: str) -> dict[str, Any]:
        if account_id not in self._accounts:
            raise KeyError(f"unknown account {account_id!r}")
        return self._accounts[account_id]
