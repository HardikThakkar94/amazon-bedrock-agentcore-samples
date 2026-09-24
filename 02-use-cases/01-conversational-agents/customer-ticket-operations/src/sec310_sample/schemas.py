"""Typed model output. Schema validation proves *shape*. It proves nothing about authority."""

from __future__ import annotations

from enum import StrEnum

from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator

from sec310_sample.errors import OutputValidationError

ACCOUNT_PATTERN = r"^acct-[a-z0-9-]{1,32}$"
RESOURCE_PATTERN = r"^(rule-[a-z0-9-]{1,32}|-)$"
MUTABLE_RULE_FIELDS = frozenset({"enabled", "name"})  # version is owned by the store


class Operation(StrEnum):
    READ_EVIDENCE = "read_evidence"
    UPDATE_RULE = "update_rule"
    DELETE_RULE = "delete_rule"


class ActionPlan(BaseModel):
    """What the model *proposes*. Executing it is somebody else's decision."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    operation: Operation
    account_id: str = Field(pattern=ACCOUNT_PATTERN)
    resource_id: str = Field(pattern=RESOURCE_PATTERN)
    reason: str = Field(min_length=1, max_length=500)
    change: dict[str, bool | str | int] | None = None

    @field_validator("change")
    @classmethod
    def _only_mutable_fields(
        cls, change: dict[str, bool | str | int] | None
    ) -> dict[str, bool | str | int] | None:
        """Arguments are validated by allow-list.

        A schema that accepts any key is a schema for surprises.
        """
        if change is None:
            return None
        unknown = sorted(set(change) - MUTABLE_RULE_FIELDS)
        if unknown:
            raise ValueError(f"change may only touch {sorted(MUTABLE_RULE_FIELDS)}, not {unknown}")
        return change

    @property
    def is_read(self) -> bool:
        return self.operation is Operation.READ_EVIDENCE

    @property
    def target_class(self) -> str:
        return "account" if self.resource_id == "-" else "rule"


class AssistantResponse(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    answer: str = Field(min_length=1, max_length=4_000)
    proposed_actions: list[ActionPlan] = Field(default_factory=list, max_length=5)
    links: list[str] = Field(default_factory=list, max_length=10)


def parse_model_output(text: str) -> AssistantResponse:
    """Strict JSON, strict schema, no prose. Anything else is a malformed response, not a hint."""
    try:
        return AssistantResponse.model_validate_json(text)
    except ValidationError as exc:
        raise OutputValidationError(f"malformed_output: {exc.error_count()} error(s)") from exc
