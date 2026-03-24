# AgentCore Identity: Gateway Inbound + Outbound Auth (CDK)

## Overview

CDK equivalent of sample 10. Deploys everything in **one `cdk deploy`**:

- **Inbound Auth**: Gateway and Runtime endpoints protected by Cognito JWT
- **Outbound Auth**: Agent authenticates to Gateway using a managed OAuth2 credential; Gateway calls the Lambda MCP server

### What CDK handles (no post-deploy scripts needed for infrastructure)

| Resource | CDK Creates |
|----------|-------------|
| Cognito User Pool + User/Agent clients | ✅ |
| Lambda MCP test server (get_time + echo) | ✅ |
| Lambda Function URL as MCP endpoint | ✅ |
| AgentCore Gateway with JWT auth | ✅ |
| AgentCore Gateway Target → Lambda URL | ✅ |
| AgentCore Runtime with JWT authorizer | ✅ |
| All IAM roles + ECR image | ✅ |

### Tutorial Details

| Information       | Details                                    |
|:------------------|:-------------------------------------------|
| Tutorial type     | Python CDK walkthrough                     |
| Framework         | Strands Agents                             |
| LLM model         | Anthropic Claude Haiku 4.5                 |
| Inbound Auth      | Amazon Cognito (CUSTOM_JWT) on Gateway + Runtime |
| Outbound Auth     | OAuth2 client credentials (managed credential) |
| CDK language      | Python                                     |

---

## Prerequisites

- **Python** 3.10+, **Node.js** 20+, **Docker**
- `npm install -g aws-cdk`

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

## Step 4: Post-deploy setup

```bash
cd ..
pip install -r requirements.txt
python setup.py
```

Creates the test user and managed gateway credential.

---

## Step 5: Test

```bash
python invoke.py "What tools do you have available?"
```

Expected output:
```
[Test 1] Without bearer token (expect AccessDeniedException)...
  Correctly rejected: ...

[Test 2] With Cognito bearer token (expect success)...
Agent response:
I have access to two gateway tools: get_time and echo.
```

---

## Step 6: Cleanup

```bash
cd cdk && cdk destroy
```
