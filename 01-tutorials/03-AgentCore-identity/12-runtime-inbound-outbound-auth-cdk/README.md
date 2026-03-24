# AgentCore Identity: Runtime Inbound + Outbound Auth (CDK)

## Overview

CDK equivalent of sample 09. Deploys everything in **one `cdk deploy`**:

- **Inbound Auth**: Runtime endpoint protected by Cognito JWT
- **Outbound Auth**: Agent retrieves an API key from AgentCore Identity at runtime

### What CDK handles (no post-deploy scripts needed for infrastructure)

| Resource | CDK Creates |
|----------|-------------|
| Cognito User Pool + App Client | ✅ |
| AgentCore Runtime with JWT authorizer | ✅ |
| IAM role with all required permissions | ✅ |
| Container image built + pushed to ECR | ✅ |

### Tutorial Details

| Information   | Details                            |
|:--------------|:-----------------------------------|
| Tutorial type | Python CDK walkthrough             |
| Agent type    | Single                             |
| Framework     | Strands Agents                     |
| LLM model     | Anthropic Claude Haiku 4.5         |
| Inbound Auth  | Amazon Cognito (CUSTOM_JWT)        |
| Outbound Auth | AgentCore Identity API key         |
| CDK language  | Python                             |

---

## Prerequisites

- **Python** 3.10+, **Node.js** 20+, **Docker** (for container build)
- **AWS CDK**: `npm install -g aws-cdk`
- **AWS credentials** configured

---

## Step 1: Install CDK dependencies

```bash
cd cdk
pip install -r requirements.txt
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

This builds the Docker image, pushes to ECR, and creates all AWS resources.

---

## Step 4: Post-deploy setup

Install requirements and create the test user + API key credential:

```bash
cd ..
pip install -r requirements.txt
python setup.py --api-key YOUR_API_KEY_HERE
```

Replace `YOUR_API_KEY_HERE` with any API key for your downstream service.

---

## Step 5: Test

```bash
python invoke.py "What is the weather in Seattle?"
```

Expected output:
```
[Test 1] Without bearer token (expect AccessDeniedException)...
  Correctly rejected: ...

[Test 2] With Cognito bearer token (expect success)...
Agent response:
The weather in Seattle is currently Sunny, 72°F.
```

---

## Step 6: Cleanup

```bash
cd cdk
cdk destroy
```

Then delete the API key credential:
```python
from bedrock_agentcore.services.identity import IdentityClient
IdentityClient(region="us-east-1").cp_client.delete_api_key_credential_provider(name="OutboundApiKey")
```
