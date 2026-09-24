"""Patch 2 — deterministic output validation.

The model can say anything. What reaches the UI, and what reaches the action layer,
is decided here with plain code: allow-listed relative routes only, no absolute URLs,
no traversal, no proposals that point outside the authenticated identity's reach.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from urllib.parse import urlsplit

from sec310_sample.identity import RequestIdentity
from sec310_sample.schemas import ActionPlan, AssistantResponse

ALLOWED_LINK_PREFIXES = ("/accounts/", "/rules/", "/cases/", "/findings/")


@dataclass(frozen=True)
class ValidatedResponse:
    answer: str
    proposed_actions: tuple[ActionPlan, ...]
    links: tuple[str, ...]
    rejected_links: tuple[tuple[str, str], ...] = field(default_factory=tuple)  # (link, reason)
    rejected_actions: tuple[tuple[ActionPlan, str], ...] = field(default_factory=tuple)


def link_rejection_reason(link: str) -> str | None:
    parts = urlsplit(link)
    if parts.scheme or parts.netloc or link.startswith("//"):
        return "absolute_url"
    if "\\" in link or any(seg == ".." for seg in parts.path.split("/")):
        return "path_traversal"
    if not link.startswith(ALLOWED_LINK_PREFIXES):
        return "route_not_allowed"
    return None


def validate_response(response: AssistantResponse, identity: RequestIdentity) -> ValidatedResponse:
    links: list[str] = []
    rejected_links: list[tuple[str, str]] = []
    for link in response.links:
        reason = link_rejection_reason(link)
        (rejected_links.append((link, reason)) if reason else links.append(link))

    actions: list[ActionPlan] = []
    rejected_actions: list[tuple[ActionPlan, str]] = []
    for plan in response.proposed_actions:
        if not identity.can_reach(plan.account_id):
            rejected_actions.append((plan, "target_not_authorized"))
        else:
            actions.append(plan)

    return ValidatedResponse(
        answer=response.answer,
        proposed_actions=tuple(actions),
        links=tuple(links),
        rejected_links=tuple(rejected_links),
        rejected_actions=tuple(rejected_actions),
    )
