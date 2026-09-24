"""Patch 3 — the model proposes; deterministic policy authorizes.

The gateway is the only path from an ``ActionPlan`` to a side effect. It checks, in
order: target reach → capability exists → confirmation → current state → policy →
idempotency → execute → audit. Every rejection is a stable token so tests and traces
can name it.
"""

from __future__ import annotations

import hashlib
import json
import time
from dataclasses import dataclass
from typing import Any

from sec310_sample.audit import AuditLog
from sec310_sample.credentials import CredentialBroker
from sec310_sample.decisions import Decision, DecisionSink, GuardedSink, no_sink
from sec310_sample.errors import AuthorizationError, PolicyRejected
from sec310_sample.identity import RequestIdentity
from sec310_sample.schemas import ActionPlan, Operation
from sec310_sample.tools.mock_read import ReadClient
from sec310_sample.tools.mock_write import WriteClient
from sec310_sample.tools.store import EvidenceStore

GATEWAY_POLICY_VERSION = "action-policy/2026.09.1"


@dataclass(frozen=True)
class Confirmation:
    action_digest: str
    confirmed_by: str


@dataclass(frozen=True)
class ActionResult:
    status: str  # ok | confirmation_required | replayed
    operation: Operation
    account_id: str
    resource_id: str
    payload: dict[str, Any] | None = None
    idempotency_key: str = ""


def action_digest(identity: RequestIdentity, plan: ActionPlan) -> str:
    """What a human confirms: this identity, this exact plan. Not 'yes' in the abstract."""
    canonical = json.dumps(
        {"who": identity.partition, "plan": plan.model_dump(mode="json")}, sort_keys=True
    )
    return hashlib.sha256(canonical.encode()).hexdigest()


def idempotency_key(identity: RequestIdentity, plan: ActionPlan) -> str:
    """Derived from the canonical action, never chosen by the model."""
    return action_digest(identity, plan)[:16]


class ActionGateway:
    def __init__(
        self,
        store: EvidenceStore,
        broker: CredentialBroker,
        audit: AuditLog | None = None,
        decision_sink: DecisionSink = no_sink,
    ) -> None:
        self._store = store
        self._broker = broker
        self.audit = audit or AuditLog()
        self._emit = GuardedSink(decision_sink)
        self._executed: dict[tuple[str, str], ActionResult] = {}  # (partition, idem key) -> result

    def execute(
        self, identity: RequestIdentity, plan: ActionPlan, confirmation: Confirmation | None = None
    ) -> ActionResult:
        t0 = time.perf_counter()
        try:
            result = self._execute(identity, plan, confirmation)
        except (AuthorizationError, PolicyRejected) as exc:
            self._decide(identity, plan, str(exc), t0)
            raise
        self._decide(identity, plan, result.status, t0)
        return result

    def _execute(
        self, identity: RequestIdentity, plan: ActionPlan, confirmation: Confirmation | None
    ) -> ActionResult:
        # 1. Reach: the target must be inside the authenticated identity's scope.
        if not identity.can_reach(plan.account_id):
            raise AuthorizationError("target_not_authorized")

        # 2. Reads: scoped read capability, no confirmation needed.
        if plan.operation is Operation.READ_EVIDENCE:
            client = ReadClient(self._store, self._broker.read_capability(identity))
            return ActionResult(
                "ok",
                plan.operation,
                plan.account_id,
                plan.resource_id,
                client.read_evidence(plan.account_id),
            )

        # 3. Capabilities that do not exist for this path cannot be borrowed.
        if plan.operation is Operation.DELETE_RULE:
            raise PolicyRejected("capability_absent:delete_not_available_to_conversation")

        # 4. Writes need a human to confirm *this* action, by digest.
        key = idempotency_key(identity, plan)
        if confirmation is None:
            return ActionResult(
                "confirmation_required",
                plan.operation,
                plan.account_id,
                plan.resource_id,
                {"action_digest": action_digest(identity, plan)},
                key,
            )
        self._verify_confirmation(identity, plan, confirmation)

        # 5. Idempotency: the same confirmed action is applied at most once.
        replay = self._executed.get((identity.partition, key))
        if replay is not None:
            return ActionResult(
                "replayed", plan.operation, plan.account_id, plan.resource_id, replay.payload, key
            )

        # 6. Current state and policy, then a scoped write capability.
        self._validate_current_state(plan)
        write_client = WriteClient(
            self._store, self._broker.write_capability(identity)
        )  # raises write_capability_not_granted
        payload = write_client.update_rule(
            plan.account_id, plan.resource_id, dict(plan.change or {})
        )

        result = ActionResult("ok", plan.operation, plan.account_id, plan.resource_id, payload, key)
        self._executed[(identity.partition, key)] = result
        self.audit.append(
            principal_partition=identity.partition,
            operation=plan.operation.value,
            account_id=plan.account_id,
            resource_id=plan.resource_id,
            confirmed_by=confirmation.confirmed_by,
            idempotency_key=key,
            result_status=result.status,
        )
        return result

    def _verify_confirmation(
        self, identity: RequestIdentity, plan: ActionPlan, confirmation: Confirmation
    ) -> None:
        if confirmation.confirmed_by != identity.principal_id:
            raise PolicyRejected("confirmation_principal_mismatch")
        if confirmation.action_digest != action_digest(identity, plan):
            raise PolicyRejected("confirmation_digest_mismatch")

    def _validate_current_state(self, plan: ActionPlan) -> None:
        try:
            current = self._store.rule(plan.account_id, plan.resource_id)
        except KeyError as exc:
            raise PolicyRejected("target_not_found") from exc
        if not plan.change:
            raise PolicyRejected("empty_change")
        if all(current.get(k) == v for k, v in plan.change.items()):
            raise PolicyRejected("no_op_change")

    def _decide(self, identity: RequestIdentity, plan: ActionPlan, outcome: str, t0: float) -> None:
        self._emit(
            Decision(
                "action",
                "action_gateway",
                outcome,
                identity,
                None,
                plan.operation.value,
                plan.target_class,
                int((time.perf_counter() - t0) * 1000),
            )
        )
