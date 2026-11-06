"""Real Strands Agent + BedrockModel ToolConfig with local fake Converse/Gateway I/O."""

from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace

import pytest
from mcp.types import Tool
from strands.tools.mcp.mcp_agent_tool import MCPAgentTool
from strands.tools.mcp.mcp_client import PaginatedList

from sec310_agent import agent as runtime

RAW = json.loads((Path(__file__).parent / "fixtures/gateway_tools_v3.json").read_text())["tools"]
ACTOR = {"user_sub": "alice-sub", "customer_id": "customer-a"}


class State:
    def __init__(self, stage="v1"):
        self.stage = stage

    def get_item(self, Key, ConsistentRead):
        return {
            "Item": {
                "customer_id": "customer-a",
                "busy_owner": "owned-run",
                "busy_stage": self.stage,
                "busy_sub": ACTOR["user_sub"],
                "policy_session": "policy-1",
                "stop_requested": False,
            }
        }


class Guardrail:
    guardrail_id = "offline"
    version = "DRAFT"
    unavailable = False

    def check(self, text):
        return "NONE", {}

    def wrap(self, text):
        return f"<untrusted>\n{text}\n</untrusted>"


class Gateway:
    instances = []

    def __init__(self, url, headers):
        assert url == "https://gateway.invalid" and headers["Authorization"] == "Bearer local"
        self.headers, self.starts, self.lists, self.sent = headers, 0, 0, []
        self.raw_tools = [MCPAgentTool(Tool(**row), self) for row in RAW]
        self.instances.append(self)

    def start(self):
        self.starts += 1

    def stop(self, *_):
        pass

    def list_tools_sync(self, pagination_token=None):
        assert pagination_token is None
        self.lists += 1
        return PaginatedList(self.raw_tools)

    async def call_tool_async(self, tool_use_id, name, arguments, **_):
        self.sent.append((name, dict(arguments)))
        assert name == "TicketTools___list_tickets"
        assert arguments == {"customer_id": "customer-a", "actor": ACTOR, "run_id": "owned-run"}
        return {
            "status": "success",
            "toolUseId": tool_use_id,
            "content": [
                {
                    "text": json.dumps(
                        {
                            "tickets": [
                                {
                                    "ticket_id": "A-41",
                                    "status": "OPEN",
                                    "subject": "Delivery delayed",
                                    "body": "Please explain the delay.",
                                    "origin": "seed",
                                },
                            ]
                        }
                    )
                }
            ],
        }


class Bedrock:
    def __init__(self):
        self.requests = []
        self.request_close = False
        self.schema_text = False
        self.first_input = {"customer_id": "customer-a"}
        self.meta = SimpleNamespace(region_name="us-east-1")

    def converse(self, **request):
        self.requests.append(request)
        assert request["modelId"] == "us.meta.llama4-maverick-17b-instruct-v1:0"
        specs = {
            entry["toolSpec"]["name"]: entry["toolSpec"] for entry in request["toolConfig"]["tools"]
        }
        for spec in specs.values():
            raw = spec["inputSchema"]["json"]
            assert "actor" not in raw["properties"] and "run_id" not in raw["properties"]
            assert set(raw["required"]) == set(raw["properties"])
            assert raw["additionalProperties"] is False
            assert all(prop["type"] == "string" for prop in raw["properties"].values())
        assert set(specs) == {
            "TicketTools___list_tickets",
            "TicketTools___close_ticket",
            "TicketTools___add_note",
        }
        if len(self.requests) == 1:
            if self.schema_text:
                answer = {"text": '[{"type": "function", "name": "TicketTools___list_tickets"}]'}
                stop = "end_turn"
            else:
                answer = {
                    "toolUse": {
                        "toolUseId": "native-read",
                        "name": "TicketTools___list_tickets",
                        "input": self.first_input,
                    }
                }
                stop = "tool_use"
        elif len(self.requests) == 2 and self.request_close:
            assert any(
                "toolResult" in entry for msg in request["messages"] for entry in msg["content"]
            )
            answer = {
                "toolUse": {
                    "toolUseId": "native-close",
                    "name": "TicketTools___close_ticket",
                    "input": {
                        "customer_id": "customer-a",
                        "ticket_id": "A-41",
                        "reason": "operator says resolved",
                    },
                }
            }
            stop = "tool_use"
        else:
            assert any(
                "toolResult" in entry for msg in request["messages"] for entry in msg["content"]
            )
            answer = {"text": "A-41 delivery remains open and needs a follow-up."}
            stop = "end_turn"
        return {
            "output": {"message": {"role": "assistant", "content": [answer]}},
            "stopReason": stop,
            "usage": {"inputTokens": 10, "outputTokens": 10, "totalTokens": 20},
            "metrics": {"latencyMs": 1},
        }


@pytest.fixture
def client(monkeypatch):
    import strands.models.bedrock as bedrock_module
    from strands import models
    from strands.models.bedrock import BedrockModel as RealBedrockModel
    from strands.tools import mcp

    monkeypatch.setattr(models, "BedrockModel", RealBedrockModel)
    Gateway.instances.clear()
    fake = Bedrock()
    session = SimpleNamespace(region_name="us-east-1", client=lambda **kw: fake)
    monkeypatch.setattr(bedrock_module.boto3, "Session", lambda: session)
    monkeypatch.setattr(mcp, "MCPClient", Gateway)
    monkeypatch.setattr(
        runtime,
        "claims_of",
        lambda token: {
            "sub": ACTOR["user_sub"],
            "customer_id": ACTOR["customer_id"],
            "role": "operator",
        },
    )
    return fake


def test_real_strands_bedrock_converse_sees_only_model_fields_then_gateway_gets_actor(client):
    result = runtime.run(
        {"run_id": "owned-run", "stage": "v1", "mode": "live", "operator": "alice"},
        "local",
        "https://gateway.invalid",
        "us.meta.llama4-maverick-17b-instruct-v1:0",
        "owned-run",
        screen=Guardrail(),
        state_table=State(),
    )
    assert len(client.requests) == 2 and len(Gateway.instances) == 1
    gateway = Gateway.instances[0]
    assert gateway.starts == gateway.lists == 1
    for raw in gateway.raw_tools:
        fixture = next(row for row in RAW if row["name"] == raw.tool_name)
        assert raw.mcp_tool.input_schema == fixture["inputSchema"]
    assert [name for name, _ in gateway.sent] == ["TicketTools___list_tickets"]
    assert result["tool_calls"][0]["status"] == "OK"
    assert result["tool_calls"][0]["input"]["actor"] == ACTOR
    assert result["controls"] == [
        {"control": "Bedrock Guardrails", "status": "NONE · text passed, wrapped in nonce tags"}
    ]
    assert "A-41 delivery" in result["answer"] and not result["blocked"]


def test_default_v0_model_still_uses_native_read_with_projected_schema(client):
    from functions.api import runs

    result = runtime.run(
        {"run_id": "owned-run", "stage": "v0", "mode": "live", "operator": "alice"},
        "local",
        "https://gateway.invalid",
        "us.meta.llama4-maverick-17b-instruct-v1:0",
        "owned-run",
        state_table=State("v0"),
    )
    assert len(client.requests) == 2
    assert [name for name, _ in Gateway.instances[0].sent] == ["TicketTools___list_tickets"]
    assert result["tool_calls"][0]["status"] == "OK"
    assert not result["controls"] and "A-41 delivery" in result["answer"]
    assert runs.run_result("v0", result, {}, {}, "live")["status"] == "NO_EFFECT"


@pytest.mark.parametrize(
    "bad_input",
    [
        {"customer_id": "customer-a", "actor": ACTOR},
        {"customer_id": "customer-a", "run_id": "model-spoof"},
        {"customer_id": True},
        {"customer_id": ["customer-a"]},
        {"customer_id": {"customer_id": "customer-a"}},
        {"customer_id": {"type": "string", "value": "customer-a"}},
    ],
)
def test_native_model_tool_use_cannot_supply_authority_or_non_string(client, bad_input):
    client.first_input = bad_input
    result = runtime.run(
        {"run_id": "owned-run", "stage": "v1", "mode": "live", "operator": "alice"},
        "local",
        "https://gateway.invalid",
        "us.meta.llama4-maverick-17b-instruct-v1:0",
        "owned-run",
        screen=Guardrail(),
        state_table=State(),
    )
    assert len(client.requests) == 2
    assert Gateway.instances[0].sent == []
    assert result["tool_calls"][0]["decision"] == "INVALID_ARGUMENTS"
    assert result["tool_calls"][0]["status"] == "NOT_EVALUATED"
    assert not result["blocked"] and not result["halted"]


def test_trusted_ask_real_model_tool_use_is_held_not_self_approved(client):
    from functions.api import runs

    client.request_close = True
    result = runtime.run(
        {
            "run_id": "owned-run",
            "stage": "v3",
            "mode": "live",
            "policy_session": "policy-1",
            "operator": "alice",
            "requests": ["A-41"],
        },
        "local",
        "https://gateway.invalid",
        "us.meta.llama4-maverick-17b-instruct-v1:0",
        "owned-run",
        screen=Guardrail(),
        state_table=State("v3"),
    )
    assert len(client.requests) == 3
    assert (
        "operator asks you to close A-41" in client.requests[0]["messages"][0]["content"][0]["text"]
    )
    assert [name for name, _ in Gateway.instances[0].sent] == ["TicketTools___list_tickets"]
    assert [c["status"] for c in result["tool_calls"]] == ["OK", "PENDING_APPROVAL"]
    assert result["tool_calls"][1]["decision"] == "PENDING_APPROVAL"
    assert not result["halted"] and not result["blocked"]
    cards = runs.approval_requests(
        "owned-run",
        result["tool_calls"],
        ("A-41",),
        [
            {
                "ticket_id": "A-41",
                "customer_id": "customer-a",
                "status": "OPEN",
                "origin": "seed",
                "subject": "Delivery delayed",
                "body": "Please explain the delay.",
            },
        ],
    )
    assert len(cards) == 1 and cards[0]["ticket_id"] == "A-41"
    assert cards[0]["status"] == "PENDING" and cards[0]["requested_by"] == "operator"
