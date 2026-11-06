"""Installed MCPAgentTool projection of the sanitized actual Gateway tools/list schema."""

from __future__ import annotations

import copy
import json
from pathlib import Path

import pytest
from mcp.types import Tool
from strands.tools.mcp.mcp_agent_tool import MCPAgentTool
from strands.tools.mcp.mcp_client import PaginatedList

from sec310_agent.agent import ARGUMENT_FIELDS
from sec310_agent.tool_projection import MODEL_TOOLS, project_gateway_tools

CAPTURE = json.loads((Path(__file__).parent / "fixtures/gateway_tools_v3.json").read_text())


class Gateway:
    def __init__(self, rows=None):
        self.tools = [MCPAgentTool(Tool(**row), self) for row in (rows or CAPTURE["tools"])]
        self.starts, self.lists = 0, 0

    def start(self):
        self.starts += 1

    def list_tools_sync(self, pagination_token=None):
        assert pagination_token is None
        self.lists += 1
        return PaginatedList(self.tools)


def test_actual_captured_gateway_schema_projects_only_model_owned_fields():
    gateway = Gateway()
    raw = copy.deepcopy([tool.mcp_tool.model_dump(by_alias=True) for tool in gateway.tools])
    projected = project_gateway_tools(gateway, ARGUMENT_FIELDS)
    assert gateway.starts == gateway.lists == 1
    assert {tool.tool_name for tool in projected} == {
        f"TicketTools___{short}" for short in MODEL_TOOLS
    }
    for tool in projected:
        short = tool.tool_name.split("___", 1)[1]
        spec = tool.tool_spec
        schema = spec["inputSchema"]["json"]
        assert schema == {
            "type": "object",
            "properties": {k: {"type": "string"} for k in ARGUMENT_FIELDS[short]},
            "required": list(ARGUMENT_FIELDS[short]),
            "additionalProperties": False,
        }
        assert tool.mcp_client is gateway and tool.mcp_tool.name == tool.tool_name
        assert tool.mcp_tool is not next(
            t.mcp_tool for t in gateway.tools if t.tool_name == tool.tool_name
        )
        assert "actor" not in schema["properties"] and "run_id" not in schema["properties"]
    assert raw == [tool.mcp_tool.model_dump(by_alias=True) for tool in gateway.tools]
    assert "TicketTools___confirm_close" not in {tool.tool_name for tool in projected}


@pytest.mark.parametrize(
    "mutation",
    [
        "missing_actor",
        "required_run_id",
        "unexpected_property",
        "wrong_customer_type",
        "actor_spoof_schema",
        "unknown_tool",
        "duplicate_tool",
        "missing_tool",
        "bad_root_type",
        "unsupported_annotations",
        "unhashable_required",
    ],
)
def test_incomplete_or_untrusted_gateway_schema_fails_before_model(mutation):
    rows = copy.deepcopy(CAPTURE["tools"])
    target = next(row for row in rows if row["name"] == "TicketTools___list_tickets")
    schema = target["inputSchema"]
    if mutation == "missing_actor":
        schema["required"].remove("actor")
    elif mutation == "required_run_id":
        schema["required"].append("run_id")
    elif mutation == "unexpected_property":
        schema["properties"]["extra"] = {"type": "string"}
    elif mutation == "wrong_customer_type":
        schema["properties"]["customer_id"]["type"] = "object"
    elif mutation == "actor_spoof_schema":
        schema["properties"]["actor"]["properties"]["user_sub"]["type"] = "number"
    elif mutation == "unknown_tool":
        rows[0]["name"] = "TicketTools___untrusted"
    elif mutation == "duplicate_tool":
        rows.append(copy.deepcopy(rows[0]))
    elif mutation == "missing_tool":
        rows.pop()
    elif mutation == "unsupported_annotations":
        target["annotations"] = {"destructiveHint": True}
    elif mutation == "unhashable_required":
        schema["required"].append(["customer-a"])
    else:
        schema["type"] = "array"
    gateway = Gateway(rows)
    with pytest.raises(ValueError, match="Gateway|schema|Tool"):
        project_gateway_tools(gateway, ARGUMENT_FIELDS)
    assert gateway.starts == gateway.lists == 1
