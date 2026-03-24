"""
Test script for sample 12 (CDK): Runtime Inbound + Outbound Auth.

Reads CDK stack outputs from cdk-outputs.json.

Usage:
    python invoke.py [prompt]
"""
import warnings
warnings.filterwarnings("ignore", category=Warning, module="requests")
warnings.filterwarnings("ignore", message="urllib3")

import boto3
import json
import sys


def load_outputs(path: str = "cdk-outputs.json") -> dict:
    try:
        with open(path) as f:
            return next(iter(json.load(f).values()))
    except FileNotFoundError:
        print(f"ERROR: {path} not found. Run 'cdk deploy --outputs-file ../cdk-outputs.json' first.")
        sys.exit(1)


def get_bearer_token(outputs: dict) -> str:
    cognito = boto3.client("cognito-idp", region_name=outputs["Region"])
    auth = cognito.initiate_auth(
        ClientId=outputs["ClientId"],
        AuthFlow="USER_PASSWORD_AUTH",
        AuthParameters={"USERNAME": "testuser", "PASSWORD": "AgentCoreTest1!"},
    )
    return auth["AuthenticationResult"]["AccessToken"]


def parse_response(response: dict) -> str:
    parts = []
    for event in response.get("response", []):
        raw = event if isinstance(event, bytes) else event.get("chunk", {}).get("bytes", b"")
        if raw:
            try:
                decoded = json.loads(raw.decode("utf-8"))
                if isinstance(decoded, str):
                    parts.append(decoded)
                elif isinstance(decoded, dict):
                    for c in decoded.get("content", []):
                        if isinstance(c, dict) and c.get("type") == "text":
                            parts.append(c["text"])
            except Exception:
                parts.append(raw.decode("utf-8"))
    return "\n".join(parts) or "(no response)"


def main():
    prompt = sys.argv[1] if len(sys.argv) > 1 else "What is the weather in Seattle?"
    outputs = load_outputs()
    region = outputs["Region"]
    runtime_arn = outputs["RuntimeArn"]
    client = boto3.client("bedrock-agentcore", region_name=region)

    print(f"Runtime: {runtime_arn}")
    print(f"Prompt: '{prompt}'\n")

    # Test 1: no token
    print("[Test 1] Without bearer token (expect AccessDeniedException)...")
    try:
        client.invoke_agent_runtime(
            agentRuntimeArn=runtime_arn, runtimeUserId="testuser",
            qualifier="DEFAULT", payload=json.dumps({"prompt": prompt}),
        )
        print("  Unexpected success")
    except client.exceptions.AccessDeniedException as e:
        print(f"  Correctly rejected: {e}")
    except Exception as e:
        print(f"  Error: {type(e).__name__}: {e}")

    # Test 2: with token
    print("\n[Test 2] With Cognito bearer token (expect success)...")
    token = get_bearer_token(outputs)
    print(f"  Token: {token[:20]}...")

    def _inject(request, **kwargs):
        request.headers["Authorization"] = f"Bearer {token}"

    client.meta.events.register("before-send.bedrock-agentcore.InvokeAgentRuntime", _inject)
    try:
        resp = client.invoke_agent_runtime(
            agentRuntimeArn=runtime_arn, runtimeUserId="testuser",
            qualifier="DEFAULT", payload=json.dumps({"prompt": prompt}),
        )
        client.meta.events.unregister("before-send.bedrock-agentcore.InvokeAgentRuntime", _inject)
        print(f"\nAgent response:\n{parse_response(resp)}")
    except Exception as e:
        print(f"  Error: {type(e).__name__}: {e}")


if __name__ == "__main__":
    main()
