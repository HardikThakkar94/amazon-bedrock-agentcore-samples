"""Patch 3 — capability credentials with a scope, a reach, and an expiry.

A ``CredentialBroker`` mints short-lived capabilities *for an identity*. Read and write
capabilities are separate objects with separate scopes. Delete is never minted for a
conversational identity: the capability does not exist, so there is nothing for a
prompt injection to borrow.
"""

from __future__ import annotations

from dataclasses import dataclass
from time import time

from sec310_sample.errors import AuthorizationError
from sec310_sample.identity import RequestIdentity
from sec310_sample.schemas import Operation

READ_SCOPE = frozenset({Operation.READ_EVIDENCE})
WRITE_SCOPE = frozenset({Operation.UPDATE_RULE})  # deliberately no DELETE_RULE
WRITE_ROLE = "responder"


@dataclass(frozen=True)
class CapabilityCredential:
    principal_partition: str
    scope: frozenset[Operation]
    accounts: frozenset[str]
    expires_at: float

    def permits(self, operation: Operation, account_id: str, now: float | None = None) -> bool:
        now = time() if now is None else now
        return operation in self.scope and account_id in self.accounts and now < self.expires_at


class CredentialBroker:
    """Stand-in for an STS-style broker. Everything it issues is derived from the identity."""

    def __init__(self, ttl_seconds: int = 300, clock=time) -> None:
        self._ttl = ttl_seconds
        self._clock = clock

    def read_capability(self, identity: RequestIdentity) -> CapabilityCredential:
        return CapabilityCredential(
            identity.partition, READ_SCOPE, identity.allowed_accounts, self._clock() + self._ttl
        )

    def write_capability(self, identity: RequestIdentity) -> CapabilityCredential:
        if WRITE_ROLE not in identity.roles:
            raise AuthorizationError("write_capability_not_granted")
        return CapabilityCredential(
            identity.partition, WRITE_SCOPE, identity.allowed_accounts, self._clock() + self._ttl
        )
