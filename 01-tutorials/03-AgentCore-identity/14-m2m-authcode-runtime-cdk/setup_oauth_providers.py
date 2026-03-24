"""
Post-deploy setup for sample 14 (CDK).

Reads CDK stack outputs and creates OAuth2 credential providers:
1. M2MProvider  — Cognito machine client (client credentials)
2. GitHub3LOProvider — GitHub OAuth2 authorization code
3. Google3LOProvider — Google OAuth2 authorization code

Usage:
    cd cdk && cdk deploy --outputs-file ../cdk-outputs.json && cd ..
    # Set credentials in .env or environment:
    export GITHUB_CLIENT_ID=...
    export GITHUB_CLIENT_SECRET=...
    export GOOGLE_CLIENT_ID=...
    export GOOGLE_CLIENT_SECRET=...
    python setup_oauth_providers.py
"""
import json
import os
import sys
import boto3
from boto3.session import Session

try:
    from dotenv import load_dotenv
    load_dotenv(override=True)
except ImportError:
    pass

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


def create_m2m_provider(identity: IdentityClient, outputs: dict) -> dict:
    region = outputs["Region"]
    pool_id = outputs["UserPoolId"]
    machine_client_id = outputs["MachineClientId"]
    discovery_url = outputs["DiscoveryUrl"]

    # Get machine client secret
    cognito = boto3.client("cognito-idp", region_name=region)
    resp = cognito.describe_user_pool_client(
        UserPoolId=pool_id, ClientId=machine_client_id
    )
    machine_secret = resp["UserPoolClient"].get("ClientSecret", "")

    print("Creating M2MProvider (Cognito client credentials)...")
    try:
        provider = identity.create_oauth2_credential_provider({
            "name": "M2MProvider",
            "credentialProviderVendor": "CustomOauth2",
            "oauth2ProviderConfigInput": {
                "customOauth2ProviderConfig": {
                    "clientId": machine_client_id,
                    "clientSecret": machine_secret,
                    "oauthDiscovery": {"discoveryUrl": discovery_url},
                }
            },
        })
        print(f"  Created: {provider.get('name')}")
    except Exception as e:
        if "already exists" in str(e).lower() or "conflict" in str(e).lower():
            print("  M2MProvider already exists.")
        else:
            raise
    return {"name": "M2MProvider"}


def create_github_provider(identity: IdentityClient) -> dict:
    client_id = os.environ.get("GITHUB_CLIENT_ID", "")
    client_secret = os.environ.get("GITHUB_CLIENT_SECRET", "")
    if not all([client_id, client_secret]):
        print("  Skipping GitHub (GITHUB_CLIENT_ID/SECRET not set).")
        return {"name": "GitHub3LOProvider", "skipped": True}

    print("Creating GitHub3LOProvider...")
    try:
     provider = identity.create_oauth2_credential_provider({
        "name": "GitHub3LOProvider",
        "credentialProviderVendor": "GithubOauth2",
        "oauth2ProviderConfigInput": {
            "githubOauth2ProviderConfig": {
                "clientId": client_id,
                "clientSecret": client_secret,
            }
        },
    })
     callback_url = provider.get("callbackUrl", "")
     print(f"  Created: {provider.get('name')}")
     print(f"\n  IMPORTANT: Add to your GitHub OAuth App -> Authorization callback URL:")
     print(f"  {callback_url}")
    except Exception as e:
     if "already exists" in str(e).lower():
      print("  GitHub3LOProvider already exists.")
      # Fetch callback URL from existing provider
      try:
       existing = identity.cp_client.get_oauth2_credential_provider(name="GitHub3LOProvider")
       callback_url = existing.get("callbackUrl", "")
       if callback_url:
        print(f"  Callback URL: {callback_url}")
        print(f"  Ensure this is registered in your GitHub OAuth App settings.")
      except Exception:
       callback_url = ""
     else:
      raise
    return {"name": "GitHub3LOProvider", "callback_url": callback_url}


def create_google_provider(identity: IdentityClient) -> dict:
    client_id = os.environ.get("GOOGLE_CLIENT_ID", "")
    client_secret = os.environ.get("GOOGLE_CLIENT_SECRET", "")
    if not all([client_id, client_secret]):
        print("  Skipping Google (GOOGLE_CLIENT_ID/SECRET not set).")
        return {"name": "Google3LOProvider", "skipped": True}

    print("Creating Google3LOProvider...")
    try:
     provider = identity.create_oauth2_credential_provider({
        "name": "Google3LOProvider",
        "credentialProviderVendor": "GoogleOauth2",
        "oauth2ProviderConfigInput": {
            "googleOauth2ProviderConfig": {
                "clientId": client_id,
                "clientSecret": client_secret,
            }
        },
    })
     callback_url = provider.get("callbackUrl", "")
     print(f"  Created: {provider.get('name')}")
     print(f"\n  IMPORTANT: Add to Google Cloud Console -> Authorised redirect URIs:")
     print(f"  {callback_url}")
    except Exception as e:
     if "already exists" in str(e).lower():
      print("  Google3LOProvider already exists.")
      try:
       existing = identity.cp_client.get_oauth2_credential_provider(name="Google3LOProvider")
       callback_url = existing.get("callbackUrl", "")
       if callback_url:
        print(f"  Callback URL: {callback_url}")
        print(f"  Ensure this is registered in Google Cloud Console -> Authorised redirect URIs.")
      except Exception:
       callback_url = ""
     else:
      raise
    return {"name": "Google3LOProvider", "callback_url": callback_url}


def create_test_user(outputs: dict):
    region = outputs["Region"]
    pool_id = outputs["UserPoolId"]
    client_id = outputs["UserClientId"]
    cognito = boto3.client("cognito-idp", region_name=region)
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
    cognito.initiate_auth(
        ClientId=client_id, AuthFlow="USER_PASSWORD_AUTH",
        AuthParameters={"USERNAME": "testuser", "PASSWORD": "AgentCoreTest1!"},
    )
    print("  Authentication verified.")


def main():
    outputs = load_outputs()
    region = outputs["Region"]
    identity = IdentityClient(region=region)

    create_test_user(outputs)

    print("\n=== M2M Provider ===")
    create_m2m_provider(identity, outputs)

    print("\n=== GitHub 3LO Provider ===")
    create_github_provider(identity)

    print("\n=== Google 3LO Provider ===")
    create_google_provider(identity)

    print("\nSetup complete.")
    print("Run: python invoke.py --flow m2m")
    print("Run: python invoke.py --flow authcode --provider github")
    print("Run: python invoke.py --flow authcode --provider google")


if __name__ == "__main__":
    main()
