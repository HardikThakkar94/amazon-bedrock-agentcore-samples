# AgentCore Identity: M2M + Auth Code Flows with Runtime (CDK)

## Overview

CDK equivalent of sample 11. Deploys everything in **one `cdk deploy`**:

- **Inbound Auth**: Runtime protected by Cognito JWT
- **M2M Outbound**: Agent calls internal API using Cognito client credentials
- **3LO Outbound**: Agent accesses GitHub repos and Google Calendar on behalf of the user

### What CDK handles (no post-deploy scripts needed for infrastructure)

| Resource | CDK Creates |
|----------|-------------|
| Cognito User Pool + User/Machine clients + Domain | ✅ |
| Cognito Resource Server for M2M scopes | ✅ |
| AgentCore Runtime with JWT authorizer | ✅ |
| CfnWorkloadIdentity with `allowedResourceOauth2ReturnUrls` | ✅ |
| IAM role with KMS token vault access (required for USER_FEDERATION) | ✅ |
| ECR container image | ✅ |

### Tutorial Details

| Information         | Details                                              |
|:--------------------|:-----------------------------------------------------|
| Tutorial type       | Python CDK walkthrough                               |
| Framework           | Strands Agents                                       |
| LLM model           | Anthropic Claude Haiku 4.5                           |
| Inbound Auth        | Amazon Cognito (CUSTOM_JWT)                          |
| Outbound M2M        | OAuth2 client credentials (Cognito machine client)   |
| Outbound 3LO        | GitHub (repo access) + Google Calendar               |
| CDK language        | Python                                               |

---

## Prerequisites

- **Python** 3.10+, **Node.js** 20+, **Docker**
- `npm install -g aws-cdk`
- GitHub OAuth App (client ID + secret)
- Google Cloud project with Calendar API enabled (client ID + secret)

---

## Step 1: Install CDK dependencies

```bash
cd cdk && pip install -r requirements.txt
```

---

## Step 2: Bootstrap CDK (once per account/region)

```bash
cdk bootstrap
```

---

## Step 3: Deploy

```bash
cdk deploy --outputs-file ../cdk-outputs.json
```

---

## Step 4: Create OAuth2 credential providers

```bash
cd ..
pip install -r requirements.txt

export GITHUB_CLIENT_ID=your-github-client-id
export GITHUB_CLIENT_SECRET=your-github-client-secret
export GOOGLE_CLIENT_ID=your-google-client-id.apps.googleusercontent.com
export GOOGLE_CLIENT_SECRET=GOCSPX-your-secret

python setup_oauth_providers.py
```

This creates test user + M2M/GitHub/Google credential providers and **prints the callback URLs**.

---

## Step 5: Register callback URLs

After running `setup_oauth_providers.py`, you'll see:

```
IMPORTANT: Add this callback URL to your GitHub OAuth App:
  https://bedrock-agentcore.us-east-1.amazonaws.com/identities/oauth2/callback/<UUID>

IMPORTANT: Add to Google Cloud Console -> Authorised redirect URIs:
  https://bedrock-agentcore.us-east-1.amazonaws.com/identities/oauth2/callback/<UUID>
```

**GitHub**: Settings → Developer settings → OAuth Apps → your app → Authorization callback URL

**Google**: Cloud Console → APIs & Services → Credentials → OAuth 2.0 Client IDs → Authorised redirect URIs

---

## Step 6: Test M2M flow

```bash
python invoke.py --flow m2m
```

Expected: Agent calls internal API using client credentials (no browser interaction).

---

## Step 7: Test GitHub 3LO flow

```bash
python invoke.py --flow authcode --provider github
```

1. Agent returns a consent URL → browser opens automatically
2. Authorize in GitHub → browser redirects to `localhost:9090`
3. Press Enter → agent lists your repos

---

## Step 8: Test Google 3LO flow

```bash
python invoke.py --flow authcode --provider google
```

Same flow as GitHub but for Google Calendar events.

---

## Step 9: Cleanup

```bash
cd cdk && cdk destroy
```

Delete credential providers:
```python
from bedrock_agentcore.services.identity import IdentityClient
ic = IdentityClient(region="us-east-1")
for name in ["M2MProvider", "GitHub3LOProvider", "Google3LOProvider"]:
    ic.cp_client.delete_oauth2_credential_provider(name=name)
```
