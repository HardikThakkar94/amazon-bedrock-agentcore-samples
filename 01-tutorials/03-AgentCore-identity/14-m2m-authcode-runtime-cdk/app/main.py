"""
AgentCore Runtime agent: M2M (client credentials) + GitHub/Google 3LO.

Inbound: Cognito JWT (configured in CDK stack).
Outbound:
  - M2M: client credentials via @requires_access_token(auth_flow="M2M")
  - GitHub 3LO: auth code via @requires_access_token(auth_flow="USER_FEDERATION")
  - Google 3LO: auth code via @requires_access_token(auth_flow="USER_FEDERATION")
"""
import json
import os
from datetime import datetime, timezone

import httpx
from strands import Agent, tool
from strands.models import BedrockModel
from bedrock_agentcore.runtime import BedrockAgentCoreApp
from bedrock_agentcore.identity.auth import requires_access_token
from bedrock_agentcore.services.identity import TokenPoller

app = BedrockAgentCoreApp()
_model = BedrockModel(model_id="us.anthropic.claude-haiku-4-5-20251001-v1:0")


class _NonBlockingPoller(TokenPoller):
    """Returns immediately so the consent URL reaches the user without blocking."""
    async def poll_for_token(self) -> str:
        return ""


# ── M2M ───────────────────────────────────────────────────────────

_m2m_token_cache: dict = {}


@requires_access_token(
    provider_name="M2MProvider",
    auth_flow="M2M",
    scopes=["https://api.m2m-demo.internal/read"],
)
async def _fetch_m2m_token(*, access_token: str) -> None:
    _m2m_token_cache["token"] = access_token


@tool
async def call_internal_api(endpoint: str) -> str:
    """Call an internal API using M2M client credentials (no user consent).

    Args:
        endpoint: The API path (e.g. /api/v1/status)
    """
    if "token" not in _m2m_token_cache:
        await _fetch_m2m_token(access_token="")
    token = _m2m_token_cache.get("token", "")
    base_url = os.environ.get("INTERNAL_API_BASE_URL", "https://api.example.internal")
    return json.dumps({
        "status": "ok",
        "endpoint": endpoint,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    })


# ── GitHub 3LO ────────────────────────────────────────────────────

_github_auth_url_cache: dict = {}


def _on_github_auth_url(url: str) -> None:
    _github_auth_url_cache["url"] = url


@tool
def get_github_repos() -> str:
    """List the authenticated user's GitHub repositories.

    On first call, returns a consent URL. After authorization, returns repos.
    """
    callback_url = os.environ.get("CALLBACK_URL", "http://localhost:9090/oauth2/callback")

    @requires_access_token(
        provider_name="GitHub3LOProvider",
        auth_flow="USER_FEDERATION",
        scopes=["repo", "read:user"],
        on_auth_url=_on_github_auth_url,
        callback_url=callback_url,
        token_poller=_NonBlockingPoller(),
    )
    def _fetch_and_list(access_token: str = "") -> str:
        if not access_token:
            auth_url = _github_auth_url_cache.get("url", "")
            if auth_url:
                return (
                    f"GitHub authorization required. Please visit:\n{auth_url}\n\n"
                    "After authorizing, invoke the agent again."
                )
            return "GitHub authorization required. Please try again."

        with httpx.Client() as client:
            user_resp = client.get(
                "https://api.github.com/user",
                headers={"Authorization": f"Bearer {access_token}"},
            )
            user_resp.raise_for_status()
            username = user_resp.json().get("login", "Unknown")
            repos_resp = client.get(
                f"https://api.github.com/search/repositories?q=user:{username}",
                headers={"Authorization": f"Bearer {access_token}"},
            )
            repos_resp.raise_for_status()
            repos = repos_resp.json().get("items", [])

        if not repos:
            return f"No repositories found for GitHub user '{username}'."
        lines = [f"GitHub repositories for {username}:"]
        for repo in repos:
            line = f"  - {repo['name']}"
            if repo.get("language"):
                line += f" ({repo['language']})"
            if repo.get("description"):
                line += f": {repo['description']}"
            lines.append(line)
        return "\n".join(lines)

    return _fetch_and_list()


# ── Google 3LO ────────────────────────────────────────────────────

_google_auth_url_cache: dict = {}


def _on_google_auth_url(url: str) -> None:
    _google_auth_url_cache["url"] = url


@tool
def get_calendar_events() -> str:
    """Get today's Google Calendar events for the authenticated user.

    On first call, returns a consent URL. After authorization, returns events.
    """
    callback_url = os.environ.get("CALLBACK_URL", "http://localhost:9090/oauth2/callback")
    today = datetime.now(timezone.utc).date().isoformat()

    @requires_access_token(
        provider_name="Google3LOProvider",
        auth_flow="USER_FEDERATION",
        scopes=["https://www.googleapis.com/auth/calendar.readonly"],
        on_auth_url=_on_google_auth_url,
        callback_url=callback_url,
        token_poller=_NonBlockingPoller(),
    )
    def _fetch_and_list(access_token: str = "") -> str:
        if not access_token:
            auth_url = _google_auth_url_cache.get("url", "")
            if auth_url:
                return (
                    f"Google authorization required. Please visit:\n{auth_url}\n\n"
                    "After authorizing, invoke the agent again."
                )
            return "Google authorization required. Please try again."

        with httpx.Client() as client:
            resp = client.get(
                "https://www.googleapis.com/calendar/v3/calendars/primary/events",
                headers={"Authorization": f"Bearer {access_token}"},
                params={
                    "timeMin": f"{today}T00:00:00Z",
                    "timeMax": f"{today}T23:59:59Z",
                    "singleEvents": "true",
                    "orderBy": "startTime",
                },
            )
            resp.raise_for_status()
            events = resp.json().get("items", [])

        if not events:
            return f"No calendar events found for today ({today})."
        lines = [f"Google Calendar events for {today}:"]
        for event in events:
            start = event.get("start", {}).get("dateTime", event.get("start", {}).get("date", ""))
            lines.append(f"  - {start}: {event.get('summary', '(no title)')}")
        return "\n".join(lines)

    return _fetch_and_list()


# ── Agent entrypoint ──────────────────────────────────────────────

_agent: Agent | None = None


@app.entrypoint
async def handler(payload: dict) -> str:
    global _agent
    if _agent is None:
        _agent = Agent(
            model=_model,
            tools=[call_internal_api, get_github_repos, get_calendar_events],
            system_prompt=(
                "You are a helpful assistant with three capabilities:\n"
                "1. call_internal_api — M2M service account (no user consent)\n"
                "2. get_github_repos — GitHub repositories (OAuth consent on first use)\n"
                "3. get_calendar_events — Google Calendar (OAuth consent on first use)\n"
                "For OAuth flows, return the authorization URL to the user."
            ),
        )
    response = _agent(payload.get("prompt", ""))
    return response.message["content"][0]["text"]


if __name__ == "__main__":
    app.run()
