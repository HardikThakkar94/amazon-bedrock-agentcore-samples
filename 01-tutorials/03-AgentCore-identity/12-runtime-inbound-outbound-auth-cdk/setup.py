"""
Post-deploy setup for sample 12 (CDK).

Reads CDK stack outputs and:
1. Creates a Cognito test user
2. Creates the outbound API key credential provider

Usage:
    cd cdk && cdk deploy --outputs-file ../cdk-outputs.json && cd ..
    python setup.py --api-key YOUR_API_KEY_HERE
"""
import argparse
import json
import sys
import boto3

try:
    from bedrock_agentcore.services.identity import IdentityClient
except ImportError:
    raise SystemExit("Install requirements first: pip install -r requirements.txt")


def load_outputs(path: str) -> dict:
    try:
        with open(path) as f:
            all_outputs = json.load(f)
        return next(iter(all_outputs.values()))
    except FileNotFoundError:
        raise SystemExit(
            f"ERROR: {path} not found.\n"
            "Run: cd cdk && cdk deploy --outputs-file ../cdk-outputs.json"
        )


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--api-key", required=True, help="API key for the outbound service")
    parser.add_argument("--outputs", default="cdk-outputs.json")
    args = parser.parse_args()

    outputs = load_outputs(args.outputs)
    region = outputs["Region"]
    pool_id = outputs["UserPoolId"]
    client_id = outputs["ClientId"]

    cognito = boto3.client("cognito-idp", region_name=region)

    print(f"Setting up in {region}...")

    # Create test user
    print("Creating test user 'testuser'...")
    try:
        cognito.admin_create_user(
            UserPoolId=pool_id, Username="testuser",
            TemporaryPassword="TempPass123!", MessageAction="SUPPRESS",
        )
        cognito.admin_set_user_password(
            UserPoolId=pool_id, Username="testuser",
            Password="AgentCoreTest1!", Permanent=True,
        )
        print("  testuser / AgentCoreTest1! created.")
    except cognito.exceptions.UsernameExistsException:
        print("  testuser already exists.")

    # Verify auth works
    cognito.initiate_auth(
        ClientId=client_id, AuthFlow="USER_PASSWORD_AUTH",
        AuthParameters={"USERNAME": "testuser", "PASSWORD": "AgentCoreTest1!"},
    )
    print("  Authentication verified.")

    # Create API key credential
    identity = IdentityClient(region=region)
    print("Creating API key credential provider 'OutboundApiKey'...")
    try:
        identity.create_api_key_credential_provider({
            "name": "OutboundApiKey",
            "apiKey": args.api_key,
        })
        print("  OutboundApiKey created.")
    except Exception as e:
        if "already exists" in str(e).lower() or "conflict" in str(e).lower():
            print("  OutboundApiKey already exists.")
        else:
            raise

    print("\nSetup complete.")
    print(f"Run: python invoke.py 'What is the weather in Seattle?'")


if __name__ == "__main__":
    main()
