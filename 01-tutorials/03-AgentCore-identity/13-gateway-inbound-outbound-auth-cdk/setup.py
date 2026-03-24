"""
Post-deploy setup for sample 13 (CDK).

Reads CDK stack outputs and:
1. Creates a Cognito test user
2. Creates the managed gateway credential (agent→gateway OAuth2)

Usage:
    cd cdk && cdk deploy --outputs-file ../cdk-outputs.json && cd ..
    python setup.py
"""
import json
import sys
import boto3

try:
    from bedrock_agentcore.services.identity import IdentityClient
except ImportError:
    raise SystemExit("Install requirements first: pip install -r requirements.txt")


def load_outputs(path: str = "cdk-outputs.json") -> dict:
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
    outputs = load_outputs()
    region = outputs["Region"]
    pool_id = outputs["UserPoolId"]
    user_client_id = outputs["UserClientId"]
    agent_client_id = outputs["AgentClientId"]
    discovery_url = outputs["DiscoveryUrl"]

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

    # Get agent client secret
    resp = cognito.describe_user_pool_client(
        UserPoolId=pool_id, ClientId=agent_client_id
    )
    agent_secret = resp["UserPoolClient"].get("ClientSecret", "")

    # Create managed gateway credential
    identity = IdentityClient(region=region)
    print("Creating managed gateway credential 'GatewayManagedCredential'...")
    try:
        identity.create_oauth2_credential_provider({
            "name": "GatewayManagedCredential",
            "credentialProviderVendor": "CustomOauth2",
            "oauth2ProviderConfigInput": {
                "customOauth2ProviderConfig": {
                    "clientId": agent_client_id,
                    "clientSecret": agent_secret,
                    "oauthDiscovery": {"discoveryUrl": discovery_url},
                }
            },
        })
        print("  GatewayManagedCredential created.")
    except Exception as e:
        if "already exists" in str(e).lower() or "conflict" in str(e).lower():
            print("  GatewayManagedCredential already exists.")
        else:
            raise

    print("\nSetup complete.")
    print("Run: python invoke.py 'What tools do you have available?'")


if __name__ == "__main__":
    main()
