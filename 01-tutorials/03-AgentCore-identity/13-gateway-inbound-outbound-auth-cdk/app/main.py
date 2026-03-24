"""
AgentCore Runtime agent: Cognito JWT inbound auth + Gateway outbound.

Inbound: Runtime validates caller's Cognito JWT (configured in CDK stack).
Outbound: Agent authenticates to the Gateway using a managed OAuth2 credential
          and calls tools through the Gateway's MCP endpoint.
"""
import os
from strands import Agent, tool
from strands.models import BedrockModel
from bedrock_agentcore.runtime import BedrockAgentCoreApp
from bedrock_agentcore.identity.auth import requires_access_token
import httpx

app = BedrockAgentCoreApp()
_model = BedrockModel(model_id="us.anthropic.claude-haiku-4-5-20251001-v1:0")

_gateway_token_cache: dict = {}


@requires_access_token(
    provider_name="GatewayManagedCredential",
    auth_flow="M2M",
    scopes=[],
)
async def _fetch_gateway_token(*, access_token: str) -> None:
    _gateway_token_cache["token"] = access_token


async def _call_mcp(method: str, params: dict) -> dict:
    if not _gateway_token_cache.get("token"):
        await _fetch_gateway_token(access_token="")
    gateway_url = os.environ.get("AGENTCORE_GATEWAY_URL", "")
    if not gateway_url:
        raise ValueError("AGENTCORE_GATEWAY_URL is not set.")
    async with httpx.AsyncClient(timeout=30) as client:
        resp = await client.post(
            gateway_url,
            json={"jsonrpc": "2.0", "method": method, "params": params, "id": 1},
            headers={
                "Authorization": f"Bearer {_gateway_token_cache['token']}",
                "Content-Type": "application/json",
            },
        )
        resp.raise_for_status()
        return resp.json().get("result", {})


@tool
async def get_time() -> str:
    """Get the current UTC time from the gateway."""
    result = await _call_mcp("tools/call", {"name": "get_time", "arguments": {}})
    content = result.get("content", [])
    return content[0].get("text", str(result)) if content else str(result)


@tool
async def echo(message: str) -> str:
    """Echo a message through the gateway.

    Args:
        message: The message to echo
    """
    result = await _call_mcp("tools/call", {"name": "echo", "arguments": {"message": message}})
    content = result.get("content", [])
    return content[0].get("text", str(result)) if content else str(result)


_agent: Agent | None = None


@app.entrypoint
async def handler(payload: dict) -> str:
    global _agent
    if _agent is None:
        _agent = Agent(
            model=_model,
            tools=[get_time, echo],
            system_prompt=(
                "You are a helpful assistant with access to two gateway tools: "
                "get_time (current UTC time) and echo (echoes a message). "
                "The gateway handles all authentication to the upstream service."
            ),
        )
    response = _agent(payload.get("prompt", ""))
    return response.message["content"][0]["text"]


if __name__ == "__main__":
    app.run()
