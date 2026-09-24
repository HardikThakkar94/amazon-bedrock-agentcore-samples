"""Append-only, hash-chained audit of every consequential action."""

from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass
from typing import Any


@dataclass(frozen=True)
class AuditRecord:
    seq: int
    prev_hash: str
    principal_partition: str
    operation: str
    account_id: str
    resource_id: str
    confirmed_by: str
    idempotency_key: str
    result_status: str
    hash: str = ""


class AuditLog:
    GENESIS = "0" * 64

    def __init__(self) -> None:
        self._records: list[AuditRecord] = []

    def append(self, **fields: Any) -> AuditRecord:
        prev = self._records[-1].hash if self._records else self.GENESIS
        body = AuditRecord(seq=len(self._records), prev_hash=prev, **fields)
        digest = hashlib.sha256(
            json.dumps({**asdict(body), "hash": ""}, sort_keys=True).encode()
        ).hexdigest()
        record = AuditRecord(**{**asdict(body), "hash": digest})
        self._records.append(record)
        return record

    def verify_chain(self) -> bool:
        prev = self.GENESIS
        for record in self._records:
            expected = hashlib.sha256(
                json.dumps({**asdict(record), "hash": ""}, sort_keys=True).encode()
            ).hexdigest()
            if record.prev_hash != prev or record.hash != expected:
                return False
            prev = record.hash
        return True

    def records(self) -> tuple[AuditRecord, ...]:
        return tuple(self._records)

    def __len__(self) -> int:
        return len(self._records)
