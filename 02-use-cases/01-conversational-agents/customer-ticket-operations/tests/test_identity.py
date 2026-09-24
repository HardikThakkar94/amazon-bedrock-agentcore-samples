"""Patch 1: identity comes from the verified token; sessions are owned, not just named."""

import pytest

from sec310_sample.errors import AuthenticationError, AuthorizationError
from sec310_sample.identity import (
    FakeAuthenticator,
    GatewayAdapter,
    RequestIdentity,
    authorize_session,
    session_partition,
)
from sec310_sample.sessions import SessionStore

ALICE = {"sub": "alice", "tenant_id": "tenant-a", "accounts": ["acct-a"], "roles": ["analyst"]}
BOB = {"sub": "bob", "tenant_id": "tenant-b", "accounts": ["acct-b"], "roles": ["analyst"]}


@pytest.fixture
def auth():
    return FakeAuthenticator()


@pytest.fixture
def gateway(auth):
    return GatewayAdapter(auth)


def bearer(auth, claims):
    return {"Authorization": f"Bearer {auth.issue(claims)}"}


def test_identity_is_derived_from_the_verified_token_not_the_body(gateway, auth):
    body = {"account_id": "acct-b", "query": "hi"}  # asks for an account it does not own

    identity = gateway.identity_from_request(bearer(auth, ALICE), body)

    assert identity == RequestIdentity(
        "tenant-a", "alice", frozenset({"acct-a"}), frozenset({"analyst"})
    )
    assert not identity.can_reach("acct-b")  # the body cannot expand capability


def test_conflicting_identity_fields_are_rejected_not_merged(gateway, auth):
    body = {"tenant_id": "tenant-b", "query": "hi"}  # token says tenant-a

    with pytest.raises(AuthorizationError, match="conflicting_identity_fields"):
        gateway.identity_from_request(bearer(auth, ALICE), body)


def test_spoofed_identity_header_is_rejected(gateway, auth):
    headers = {**bearer(auth, ALICE), "X-Tenant-Id": "tenant-b"}

    with pytest.raises(AuthorizationError, match="conflicting_identity_fields"):
        gateway.identity_from_request(headers, {})


@pytest.mark.parametrize(
    "header, value",
    [("X-Tenant-Id", "tenant-b"), ("X-Principal-Id", "bob"), ("X-Accounts", "acct-a,acct-b")],
)
def test_every_caller_identity_header_is_checked_symmetrically(gateway, auth, header, value):
    with pytest.raises(AuthorizationError, match="conflicting_identity_fields"):
        gateway.identity_from_request({**bearer(auth, ALICE), header: value}, {})

    agreeing = {"X-Tenant-Id": "tenant-a", "X-Principal-Id": "alice", "X-Accounts": "acct-a"}
    assert (
        gateway.identity_from_request({**bearer(auth, ALICE), **agreeing}, {}).principal_id
        == "alice"
    )


def test_forward_returns_identity_and_stripped_headers(gateway, auth):
    headers = {**bearer(auth, ALICE), "X-Tenant-Id": "tenant-a", "X-Request-Id": "r1"}

    identity, forwarded = gateway.forward(headers, {})

    assert identity.tenant_id == "tenant-a"
    assert set(forwarded) == {"X-Request-Id"}  # the token and identity claims stay at the boundary


def test_caller_identity_headers_are_stripped_before_forwarding(gateway):
    forwarded = gateway.strip_caller_identity_headers(
        {"X-Tenant-Id": "tenant-b", "X-Request-Id": "r1", "Authorization": "Bearer x"}
    )

    assert "X-Tenant-Id" not in forwarded
    assert forwarded["X-Request-Id"] == "r1"


def test_tampered_token_fails_authentication(gateway, auth):
    token = auth.issue(ALICE)
    payload, sig = token.split(".")
    forged = f"{payload}.{'0' * len(sig)}"

    with pytest.raises(AuthenticationError, match="invalid_signature"):
        gateway.identity_from_request({"Authorization": f"Bearer {forged}"}, {})


def test_principals_cannot_share_session_state():
    alice = RequestIdentity("tenant-a", "alice", frozenset({"acct-a"}))
    bob = RequestIdentity(
        "tenant-a", "bob", frozenset({"acct-a"})
    )  # same tenant, still not the owner
    stored = session_partition(alice, "session-1")

    with pytest.raises(AuthorizationError, match="session_not_owned"):
        authorize_session(bob, "session-1", stored)


def test_session_store_enforces_ownership_on_every_access():
    store = SessionStore()
    alice = RequestIdentity("tenant-a", "alice", frozenset({"acct-a"}))
    bob = RequestIdentity("tenant-b", "bob", frozenset({"acct-b"}))
    store.get_or_create(alice, "session-1").turns.append("alice's first turn")

    with pytest.raises(AuthorizationError, match="session_not_owned"):
        store.get_or_create(bob, "session-1")  # bob guessed the id
    with pytest.raises(AuthorizationError, match="session_not_owned"):
        store.append_turn(bob, "session-1", "bob writes into alice's history")

    assert store.get(alice, "session-1").turns == ["alice's first turn"]
    assert len(store) == 1
