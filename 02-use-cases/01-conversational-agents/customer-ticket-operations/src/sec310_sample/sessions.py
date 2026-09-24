"""Patch 1 — sessions are authorization domains.

A session id is a lookup hint, not a proof of ownership. Every read and write checks
that the stored partition matches the authenticated identity. Knowing (or guessing)
another principal's session id gets you exactly nothing.

The sample accepts client-chosen session ids to keep fixtures readable. In production,
issue them server-side: a client-chosen, guessable id lets an attacker pre-claim it and
deny the legitimate owner (a nuisance, never a disclosure, because ownership still wins).
"""

from __future__ import annotations

from dataclasses import dataclass, field

from sec310_sample.errors import AuthorizationError
from sec310_sample.identity import RequestIdentity, authorize_session, session_partition


@dataclass
class SessionRecord:
    partition: str
    session_id: str
    turns: list[str] = field(default_factory=list)


class SessionStore:
    """In-memory stand-in for a partitioned session table."""

    def __init__(self) -> None:
        self._records: dict[str, SessionRecord] = {}  # partition -> record
        self._owner_of: dict[str, str] = {}  # session_id -> partition

    def get_or_create(self, identity: RequestIdentity, session_id: str) -> SessionRecord:
        partition = session_partition(identity, session_id)
        owner = self._owner_of.get(session_id)
        if owner is None:
            record = SessionRecord(partition=partition, session_id=session_id)
            self._records[partition] = record
            self._owner_of[session_id] = partition
            return record
        authorize_session(identity, session_id, owner)  # raises session_not_owned
        return self._records[owner]

    def get(self, identity: RequestIdentity, session_id: str) -> SessionRecord:
        owner = self._owner_of.get(session_id)
        if owner is None:
            raise KeyError(session_id)
        authorize_session(identity, session_id, owner)
        return self._records[owner]

    def append_turn(self, identity: RequestIdentity, session_id: str, text: str) -> None:
        self.get(identity, session_id).turns.append(text)

    def owner_partition(self, session_id: str) -> str | None:
        return self._owner_of.get(session_id)

    def __len__(self) -> int:
        return len(self._records)


def require_owned(store: SessionStore, identity: RequestIdentity, session_id: str) -> SessionRecord:
    try:
        return store.get(identity, session_id)
    except KeyError as exc:
        raise AuthorizationError("session_unknown") from exc
