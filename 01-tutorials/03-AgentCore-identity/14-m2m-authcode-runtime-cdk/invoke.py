"""
Test script for sample 14 (CDK): M2M + Auth Code Flows.

Reads CDK stack outputs from cdk-outputs.json.

Usage:
    python invoke.py --flow m2m
    python invoke.py --flow authcode --provider github
    python invoke.py --flow authcode --provider google
"""
import warnings
warnings.filterwarnings("ignore", category=Warning, module="requests")
warnings.filterwarnings("ignore", message="urllib3")

import argparse
import json
import re
import subprocess
import sys
import webbrowser

import boto3

from oauth2_callback_server import (
    get_oauth2_callback_url,
    store_token_in_oauth2_callback_server,
    wait_for_oauth2_server_to_be_ready,
)


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
        ClientId=outputs["UserClientId"],
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


def invoke(client, runtime_arn: str, prompt: str, token: str, user_id: str) -> str:
    def _inject(request, **kwargs):
        request.headers["Authorization"] = f"Bearer {token}"

    client.meta.events.register("before-send.bedrock-agentcore.InvokeAgentRuntime", _inject)
    resp = client.invoke_agent_runtime(
        agentRuntimeArn=runtime_arn, runtimeUserId=user_id,
        qualifier="DEFAULT", payload=json.dumps({"prompt": prompt}),
    )
    client.meta.events.unregister("before-send.bedrock-agentcore.InvokeAgentRuntime", _inject)
    return parse_response(resp)


def test_m2m(client, runtime_arn: str, token: str, outputs: dict):
    print("\n=== M2M Flow ===")
    prompt = "Check the status of the internal API at /api/v1/status"
    print(f"Prompt: '{prompt}'")
    result = invoke(client, runtime_arn, prompt, token, "testuser")
    print(f"\nAgent response:\n{result}")


def test_authcode(client, runtime_arn: str, token: str, outputs: dict, provider: str):
    config = {
        "github": {
            "prompt": "List my GitHub repositories.",
            "keywords": ["github", "oauth", "http"],
            "wait_msg": "Waiting for GitHub consent...",
            "reinvoke_msg": "Re-invoking to retrieve repositories...",
        },
        "google": {
            "prompt": "What is on my Google Calendar today?",
            "keywords": ["google", "oauth", "http"],
            "wait_msg": "Waiting for Google consent...",
            "reinvoke_msg": "Re-invoking to retrieve calendar events...",
        },
    }
    cfg = config[provider]

    print(f"\n=== Auth Code Flow — {provider.capitalize()} ===")
    print("Starting OAuth2 callback server...")

    server_proc = subprocess.Popen(
        [sys.executable, "oauth2_callback_server.py", "--region", outputs["Region"]],
    )

    try:
        if not wait_for_oauth2_server_to_be_ready():
            print("ERROR: Callback server did not start.")
            return

        store_token_in_oauth2_callback_server(token)
        print(f"  Callback URL: {get_oauth2_callback_url()}")

        prompt = cfg["prompt"]
        print(f"\nPrompt: '{prompt}'")
        print("Invoking agent (first call — expect consent URL)...")

        result = invoke(client, runtime_arn, prompt, token, "testuser")
        print(f"\nAgent response:\n{result}")

        result_lower = result.lower()
        if "http" in result_lower and any(k in result_lower for k in cfg["keywords"]):
            urls = re.findall(r"https?://[^\s'\")*\]]+", result)
            if urls:
                consent_url = urls[0]
                print(f"\nConsent URL: {consent_url}")
                print("Opening in your browser...")
                webbrowser.open(consent_url)

            print(f"\n{cfg['wait_msg']}")
            print("After authorizing, press Enter to re-invoke.")
            input()

            print(cfg["reinvoke_msg"])
            result2 = invoke(client, runtime_arn, prompt, token, "testuser")
            print(f"\nAgent response:\n{result2}")

    finally:
        server_proc.terminate()
        server_proc.wait()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--flow", choices=["m2m", "authcode", "both"], default="both")
    parser.add_argument("--provider", choices=["github", "google"], default="google")
    args = parser.parse_args()

    outputs = load_outputs()
    region = outputs["Region"]
    runtime_arn = outputs["RuntimeArn"]

    print("Getting Cognito bearer token...")
    token = get_bearer_token(outputs)
    print(f"  Token: {token[:20]}...")

    client = boto3.client("bedrock-agentcore", region_name=region)

    if args.flow in ("m2m", "both"):
        test_m2m(client, runtime_arn, token, outputs)

    if args.flow in ("authcode", "both"):
        test_authcode(client, runtime_arn, token, outputs, args.provider)


if __name__ == "__main__":
    main()
