"""AgentCore Runtime entrypoint for the support agent (container, port 8080).

The Runtime's JWT authorizer has verified the caller's Cognito access token before this code runs;
the token arrives in ``context.request_headers`` because the Runtime allowlists ``Authorization``.
"""

from __future__ import annotations

import logging
import os
from typing import Any

from bedrock_agentcore.runtime import BedrockAgentCoreApp

from sec310_agent.agent import bearer, run

app = BedrockAgentCoreApp()
log = logging.getLogger("sec310_agent")


@app.entrypoint
def invoke(payload: dict[str, Any], context: Any) -> dict[str, Any]:
    # The second parameter must be named ``context`` for the SDK to pass the request context.
    try:
        token = bearer(getattr(context, "request_headers", None))
    except PermissionError as exc:
        return {"error": str(exc)}
    result = run(
        payload or {},
        token,
        gateway_url=os.environ["GATEWAY_URL"],
        model_id=os.environ["MODEL_ID"],
        session_id=getattr(context, "session_id", None),
    )
    log.info("run %s: %d tool calls", result["run_id"], len(result["tool_calls"]))
    return result


if __name__ == "__main__":
    app.run()
