"""
AgentCore Runtime agent: Cognito JWT inbound auth + API key outbound.

Inbound: Runtime validates caller's Cognito JWT (configured in CDK stack).
Outbound: @requires_api_key fetches the API key from AgentCore Identity
          at runtime — never stored in environment variables.
"""
import json
import os
from datetime import datetime, timezone

from strands import Agent, tool
from strands.models import BedrockModel
from bedrock_agentcore.runtime import BedrockAgentCoreApp
from bedrock_agentcore.identity.auth import requires_api_key

app = BedrockAgentCoreApp()
_model = BedrockModel(model_id="us.anthropic.claude-haiku-4-5-20251001-v1:0")


@tool
def get_weather(location: str) -> str:
    """Get the weather for a location using a secure outbound API key.

    Args:
        location: City or location name
    """
    @requires_api_key(provider_name="OutboundApiKey")
    def _fetch(*, api_key: str) -> str:
        base_url = os.environ.get("WEATHER_API_BASE_URL", "https://api.weather.example")
        # In production, use api_key to call a real weather API
        return json.dumps({
            "location": location,
            "weather": "Sunny",
            "temperature": "72°F",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "source": base_url,
        })
    return _fetch()


_agent: Agent | None = None


@app.entrypoint
async def handler(payload: dict) -> str:
    global _agent
    if _agent is None:
        _agent = Agent(
            model=_model,
            tools=[get_weather],
            system_prompt="You are a helpful weather assistant.",
        )
    response = _agent(payload.get("prompt", ""))
    return response.message["content"][0]["text"]


if __name__ == "__main__":
    app.run()
