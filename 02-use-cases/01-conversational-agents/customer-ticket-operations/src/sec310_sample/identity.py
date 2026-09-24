"""Patch 1 — identity before agency.

Identity is derived once, at the authenticated boundary, from a *verified* token.
It is immutable, it travels with the request, and nothing the caller puts in a body
or a spoofable header can widen it. The model never sees a credential; it only ever
sees the consequences of identity (which tools exist, which accounts they reach).
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import secrets
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

from sec310_sample.errors import AuthenticationError, AuthorizationError

# Headers a caller might send to *claim* an identity. The gateway strips them; the
# only source of truth is the verified token.
CALLER_IDENTITY_HEADERS = ("x-tenant-id", "x-principal-id", "x-accounts")


@dataclass(frozen=True)
class RequestIdentity:
    tenant_id: str
    principal_id: str
    allowed_accounts: frozenset[str]
    roles: frozenset[str] = frozenset()

    def can_reach(self, account_id: str) -> bool:
        return account_id in self.allowed_accounts

    @property
    def partition(self) -> str:
        return f"tenant/{self.tenant_id}/principal/{self.principal_id}"


def session_partition(identity: RequestIdentity, session_id: str) -> str:
    """The storage key for session state. Ownership is *in the key*, not next to it."""
    return f"{identity.partition}/session/{session_id}"


def authorize_session(identity: RequestIdentity, session_id: str, stored_partition: str) -> None:
    if not hmac.compare_digest(stored_partition, session_partition(identity, session_id)):
        raise AuthorizationError("session_not_owned")


class FakeAuthenticator:
    """Issues and verifies HMAC-signed tokens for the demo.

    Stands in for whatever real identity provider sits in front of the agent. The key
    is generated per process; there is no shared secret to leak.
    """

    def __init__(self) -> None:
        self._key = secrets.token_bytes(32)

    def issue(self, claims: Mapping[str, Any]) -> str:
        payload = _b64(json.dumps(dict(claims), sort_keys=True, separators=(",", ":")).encode())
        return f"{payload}.{self._sign(payload)}"

    def verify(self, token: str) -> dict[str, Any]:
        try:
            payload, signature = token.split(".", 1)
        except ValueError as exc:
            raise AuthenticationError("malformed_token") from exc
        if not hmac.compare_digest(signature, self._sign(payload)):
            raise AuthenticationError("invalid_signature")
        return json.loads(_unb64(payload))

    def _sign(self, payload: str) -> str:
        return hmac.new(self._key, payload.encode(), hashlib.sha256).hexdigest()


class GatewayAdapter:
    """The authenticated boundary. Everything downstream trusts only its output."""

    def __init__(self, authenticator: FakeAuthenticator) -> None:
        self._auth = authenticator

    def identity_from_request(
        self, headers: Mapping[str, str], body: Mapping[str, Any]
    ) -> RequestIdentity:
        token = _bearer(headers)
        claims = self._auth.verify(token)
        identity = RequestIdentity(
            tenant_id=claims["tenant_id"],
            principal_id=claims["sub"],
            allowed_accounts=frozenset(claims.get("accounts", ())),
            roles=frozenset(claims.get("roles", ())),
        )
        # Caller-supplied identity fields are never merged. If they disagree with the
        # verified identity, that is a signal, not a preference.
        for field in ("tenant_id", "principal_id"):
            if field in body and body[field] != getattr(identity, field):
                raise AuthorizationError("conflicting_identity_fields")
        lowered = {k.lower(): v for k, v in headers.items()}
        asserted = {
            "x-tenant-id": identity.tenant_id,
            "x-principal-id": identity.principal_id,
            "x-accounts": ",".join(sorted(identity.allowed_accounts)),
        }
        for header, truth in asserted.items():
            value = lowered.get(header)
            if value is None:
                continue
            normalized = (
                ",".join(sorted(v.strip() for v in value.split(",")))
                if header == "x-accounts"
                else value
            )
            if normalized != truth:
                raise AuthorizationError("conflicting_identity_fields")
        return identity

    def forward(
        self, headers: Mapping[str, str], body: Mapping[str, Any]
    ) -> tuple[RequestIdentity, dict[str, str]]:
        """The gateway contract: a verified identity plus headers safe to forward downstream.

        The bearer token is consumed here, at the boundary. Downstream services get the
        verified identity, not the credential that produced it.
        """
        identity = self.identity_from_request(headers, body)
        return identity, self.strip_caller_identity_headers(headers)

    @staticmethod
    def strip_caller_identity_headers(headers: Mapping[str, str]) -> dict[str, str]:
        """Used by ``forward``: the request minus the token and anything that merely *claims* identity."""
        drop = {*CALLER_IDENTITY_HEADERS, "authorization"}
        return {k: v for k, v in headers.items() if k.lower() not in drop}


def _bearer(headers: Mapping[str, str]) -> str:
    for key, value in headers.items():
        if key.lower() == "authorization" and value.lower().startswith("bearer "):
            return value[7:].strip()
    raise AuthenticationError("missing_bearer_token")


def _b64(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")


def _unb64(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))
