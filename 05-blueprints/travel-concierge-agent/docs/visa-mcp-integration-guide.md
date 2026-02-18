# Visa MCP Server Integration Guide

Complete instructions for deploying and integrating the Visa MCP server with your agent infrastructure.

## Overview

This guide covers:
- Deployment architecture
- AWS Secrets Manager setup
- CDK deployment commands
- Server configuration and health checks
- Integration with AgentCore
- Troubleshooting common issues

---

## Architecture

### Components

```
┌─────────────────────────────────────────────────────────┐
│                    Agent Framework                       │
│  (AgentCore, Bedrock Agents, Supervisor Agent)         │
└──────────────────────┬──────────────────────────────────┘
                       │
                       │ MCP Protocol (HTTP)
                       │
┌──────────────────────▼──────────────────────────────────┐
│           Visa MCP Server (FastMCP)                     │
│  ┌──────────────────────────────────────────────────┐  │
│  │ 10 Visa Tools                                    │  │
│  │ - Tokenization & Onboarding                      │  │
│  │ - Device Security (Attestation, Binding)         │  │
│  │ - VIC Payment Flow                               │  │
│  │ - FIDO/Passkey Support                           │  │
│  └──────────────────────────────────────────────────┘  │
└──────────────────────┬──────────────────────────────────┘
                       │
                       │ HTTPS/TLS
                       │
┌──────────────────────▼──────────────────────────────────┐
│           Visa API (VTS, VIC, OAuth)                   │
│  - Card Enrollment & Tokenization                      │
│  - Device Attestation                                  │
│  - Payment Instructions                                │
│  - Payment Credentials                                 │
└──────────────────────────────────────────────────────────┘
```

### Security Layers

1. **Agent Authorization**: Only registered agents can access tools
2. **Secrets Management**: All API keys stored in AWS Secrets Manager
3. **TLS Encryption**: All Visa API calls use TLS 1.2+
4. **Payload Encryption**: Card data encrypted before transmission
5. **Signature Validation**: HMAC signatures on all API requests

---

## Prerequisites

### AWS Requirements

- AWS Account with appropriate IAM permissions
- AWS region: `us-east-1` (configurable in code)
- AWS CLI configured locally for deployment
- CDK v2 installed: `npm install -g aws-cdk@latest`

### Required IAM Permissions

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "secretsmanager:GetSecretValue",
        "secretsmanager:CreateSecret",
        "secretsmanager:PutSecretValue"
      ],
      "Resource": "arn:aws:secretsmanager:us-east-1:ACCOUNT_ID:secret:visa/*"
    },
    {
      "Effect": "Allow",
      "Action": [
        "ec2:DescribeSecurityGroups",
        "ec2:DescribeSubnets",
        "ec2:DescribeVpcs"
      ],
      "Resource": "*"
    },
    {
      "Effect": "Allow",
      "Action": [
        "ecs:CreateCluster",
        "ecs:RegisterTaskDefinition",
        "ecs:CreateService",
        "logs:CreateLogGroup",
        "logs:CreateLogStream",
        "logs:PutLogEvents"
      ],
      "Resource": "*"
    }
  ]
}
```

### Visa Account Requirements

- Visa Developer Portal account (sandbox)
- VTS API credentials (API key, shared secret)
- VTS Encryption credentials (encryption API key, shared secret)
- VIC API credentials (if using payment instructions)
- Visa OAuth credentials
- Test card numbers from Visa documentation

---

## Secrets Manager Setup

### Secret Organization

All Visa secrets are stored under the `visa/` path prefix:

```
visa/
├── api-key                    # VTS API key
├── shared-secret              # VTS HMAC shared secret
├── encryption-api-key         # Encryption API key
├── encryption-shared-secret   # Encryption shared secret
├── server-mle-cert            # VIC server certificate (PEM)
├── mle-private-cert           # VIC private key (PEM)
└── vic_key_id                 # VIC key identifier
```

### Creating Secrets

#### Step 1: VTS Credentials

```bash
# API Key
aws secretsmanager create-secret \
  --name visa/api-key \
  --secret-string "your-vts-api-key-here" \
  --region us-east-1

# Shared Secret
aws secretsmanager create-secret \
  --name visa/shared-secret \
  --secret-string "your-vts-shared-secret-here" \
  --region us-east-1

# Encryption API Key
aws secretsmanager create-secret \
  --name visa/encryption-api-key \
  --secret-string "your-encryption-api-key-here" \
  --region us-east-1

# Encryption Shared Secret
aws secretsmanager create-secret \
  --name visa/encryption-shared-secret \
  --secret-string "your-encryption-shared-secret-here" \
  --region us-east-1
```

#### Step 2: Certificates (VIC)

```bash
# Server Certificate (from Visa portal - download as PEM)
# Replace newlines with literal \n for CLI storage
aws secretsmanager create-secret \
  --name visa/server-mle-cert \
  --secret-string "$(cat server-cert.pem | sed 's/$/\\n/g' | tr -d '\n')" \
  --region us-east-1

# Private Key
aws secretsmanager create-secret \
  --name visa/mle-private-cert \
  --secret-string "$(cat private-key.pem | sed 's/$/\\n/g' | tr -d '\n')" \
  --region us-east-1

# VIC Key ID
aws secretsmanager create-secret \
  --name visa/vic_key_id \
  --secret-string "your-vic-key-id-here" \
  --region us-east-1
```

#### Step 3: Verify Secrets Created

```bash
# List all visa secrets
aws secretsmanager list-secrets \
  --filters Key=name,Values=visa/ \
  --region us-east-1

# Verify specific secret can be retrieved
aws secretsmanager get-secret-value \
  --secret-id visa/api-key \
  --region us-east-1
```

### Secret Rotation Strategy

Implement secret rotation every 90 days:

```bash
# Create new version
aws secretsmanager put-secret-value \
  --secret-id visa/api-key \
  --secret-string "new-api-key-value" \
  --region us-east-1

# Update configuration to use new version
# Restart MCP server to pick up new secret
```

---

## CDK Deployment

### Project Structure

```
infrastructure/mcp-servers/
├── lib/
│   ├── visa-stack.ts         # Visa MCP server stack
│   ├── base-mcp-stack.ts     # Base configuration
│   └── app.ts                # CDK app
├── bin/
│   └── app.ts                # Entry point
├── cdk.json                  # Context values
└── package.json              # Dependencies
```

### Configuration (cdk.json)

```json
{
  "context": {
    "vtsApiKey": "visa/api-key",
    "vtsSharedSecret": "visa/shared-secret",
    "encryptionApiKey": "visa/encryption-api-key",
    "encryptionSharedSecret": "visa/encryption-shared-secret",
    "visaServerCert": "visa/server-mle-cert",
    "visaPrivateKey": "visa/mle-private-cert",
    "vicKeyId": "visa/vic_key_id",
    "region": "us-east-1",
    "containerPort": 5000,
    "environment": "dev"
  }
}
```

### Deployment Steps

#### Step 1: Bootstrap CDK (First Time Only)

```bash
cd infrastructure/mcp-servers

# Bootstrap CDK in your AWS account
cdk bootstrap aws://ACCOUNT_ID/us-east-1
```

#### Step 2: Install Dependencies

```bash
# Install npm dependencies
npm install

# Verify TypeScript compilation
npm run build
```

#### Step 3: Review Infrastructure

```bash
# Synthesize CDK to CloudFormation
cdk synth

# Review differences before deployment
cdk diff
```

#### Step 4: Deploy

```bash
# Deploy the Visa MCP stack
cdk deploy VisaStack \
  --require-approval=never \
  --profile default

# Or with automatic approval for CI/CD
cdk deploy VisaStack \
  --require-approval=never \
  --concurrency=1
```

#### Step 5: Get Deployment Info

```bash
# List deployed stacks
aws cloudformation list-stacks \
  --region us-east-1 \
  --query 'StackSummaries[?StackStatus==`CREATE_COMPLETE`]'

# Get stack outputs (including service URL)
aws cloudformation describe-stacks \
  --stack-name VisaStack \
  --region us-east-1 \
  --query 'Stacks[0].Outputs'
```

### Stack Outputs

The CDK deployment creates outputs that can be referenced:

```
Outputs:
  VisaServiceURL: http://visa-mcp-service.internal:5000
  VisaServiceEndpoint: http://load-balancer-xxx.us-east-1.elb.amazonaws.com:5000
  CloudWatchLogGroup: /ecs/visa-mcp-server
```

---

## Server Configuration

### Environment Variables

Set these in the ECS task definition:

```bash
# AWS Configuration
AWS_REGION=us-east-1
AWS_ACCOUNT_ID=123456789012

# Server Configuration
SERVER_NAME=Visa Tools
SERVER_HOST=0.0.0.0
SERVER_PORT=5000
STATELESS_HTTP=true

# Visa Configuration (Secret Names)
VISA_API_KEY_SECRET=visa/api-key
VISA_SHARED_SECRET=visa/shared-secret
VISA_ENCRYPTION_API_KEY=visa/encryption-api-key
VISA_ENCRYPTION_SHARED_SECRET=visa/encryption-shared-secret
VISA_SERVER_CERT_SECRET=visa/server-mle-cert
VISA_PRIVATE_KEY_SECRET=visa/mle-private-cert
VISA_VIC_KEY_ID_SECRET=visa/vic_key_id

# Logging
LOG_LEVEL=INFO
PYTHONUNBUFFERED=1
```

### Docker Image

The server runs in a Docker container:

```dockerfile
FROM python:3.11-slim

WORKDIR /app

# Install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application
COPY . .

# Set environment
ENV PYTHONUNBUFFERED=1
ENV AWS_REGION=us-east-1

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=10s --retries=3 \
  CMD curl -f http://localhost:5000/health || exit 1

# Run server
CMD ["python", "concierge_agent/mcp_visa_tools/server.py"]
```

### Requirements

```
mcp>=0.5.0
fastapi>=0.104.0
uvicorn>=0.24.0
boto3>=1.26.0
requests>=2.31.0
jwcrypto>=1.5.0
python-multipart>=0.0.6
```

---

## Testing the MCP Server

### Health Check

```bash
# Test server is running
curl http://localhost:5000/health

# Expected response:
# {
#   "status": "healthy",
#   "service": "visa-mcp",
#   "tools": 10
# }
```

### Tool Discovery

```bash
# Get list of available tools
curl http://localhost:5000/tools

# Expected response includes all 10 tools with descriptions
```

### Local Testing

#### Option 1: Docker Container

```bash
# Build image
docker build -t visa-mcp:latest .

# Run container
docker run -p 5000:5000 \
  -e AWS_REGION=us-east-1 \
  -e AWS_PROFILE=default \
  -v ~/.aws:/root/.aws:ro \
  visa-mcp:latest

# Test from another terminal
curl http://localhost:5000/health
```

#### Option 2: Local Python

```bash
# Install dependencies
pip install -r requirements.txt

# Export AWS credentials
export AWS_PROFILE=default

# Run server
cd concierge_agent/mcp_visa_tools
python server.py

# In another terminal, test
python -c "
from server import mcp
from tools import visa_get_secure_token
result = visa_get_secure_token()
print(result)
"
```

### Integration Testing

```python
# test_visa_mcp.py
import requests
import json

BASE_URL = "http://localhost:5000"

def test_health():
    response = requests.get(f"{BASE_URL}/health")
    assert response.status_code == 200
    assert response.json()["status"] == "healthy"
    print("✓ Health check passed")

def test_secure_token():
    response = requests.post(
        f"{BASE_URL}/tools/visa_get_secure_token",
        json={"clientAppId": "VICTestAccountTR"}
    )
    assert response.status_code == 200
    data = response.json()
    assert data["success"] == True
    assert "secureToken" in data
    print("✓ Secure token retrieval passed")

def test_onboard_card():
    response = requests.post(
        f"{BASE_URL}/tools/visa_onboard_card",
        json={
            "email": "test@example.com",
            "accountNumber": "4111111111111111",
            "cvv2": "123",
            "expirationDate": "2025-12"
        }
    )
    assert response.status_code == 200
    data = response.json()
    assert data["success"] == True
    assert "vProvisionedTokenID" in data
    print("✓ Card onboarding passed")

if __name__ == "__main__":
    test_health()
    test_secure_token()
    test_onboard_card()
    print("\nAll tests passed!")
```

Run tests:

```bash
pip install requests
python test_visa_mcp.py
```

---

## Integration with AgentCore

### Agent Tool Calling

Agents call the Visa MCP tools through the MCP protocol:

```python
# In your agent code
from mcp.client import MCPClient

class VisaPaymentAgent:
    def __init__(self, mcp_url="http://localhost:5000"):
        self.client = MCPClient(base_url=mcp_url)

    async def process_payment(self, user_email, card_data):
        # Get secure token
        token_result = await self.client.call_tool(
            "visa_get_secure_token",
            {"clientAppId": "VICTestAccountTR"}
        )

        if not token_result["success"]:
            raise Exception(f"Failed to get token: {token_result['error']}")

        secure_token = token_result["secureToken"]

        # Onboard card
        onboard_result = await self.client.call_tool(
            "visa_onboard_card",
            {
                "email": user_email,
                "accountNumber": card_data["pan"],
                "cvv2": card_data["cvv"],
                "expirationDate": card_data["expiry"]
            }
        )

        if not onboard_result["success"]:
            raise Exception(f"Card onboarding failed: {onboard_result['error']}")

        return onboard_result["vProvisionedTokenID"]
```

### Tool Result Parsing

All tools return consistent response structure:

```python
# Success response
{
    "success": True,
    "data_field_1": "value1",
    "data_field_2": "value2"
}

# Error response
{
    "success": False,
    "error": "Human-readable error message"
}
```

### Error Handling

Implement proper error handling in your agent:

```python
async def safe_tool_call(tool_name, params):
    try:
        result = await client.call_tool(tool_name, params)
        if not result["success"]:
            logger.error(f"Tool {tool_name} failed: {result['error']}")
            # Handle specific error types
            if "timeout" in result["error"].lower():
                # Retry with backoff
                return await retry_with_backoff(tool_name, params)
            elif "invalid token" in result["error"].lower():
                # Restart authentication flow
                return await restart_auth_flow()
            else:
                # Business logic error, propagate to user
                raise Exception(result["error"])
        return result
    except Exception as e:
        logger.exception(f"Tool call failed: {e}")
        raise
```

---

## Monitoring & Logging

### CloudWatch Logs

View logs from ECS task:

```bash
# View recent logs
aws logs tail /ecs/visa-mcp-server --follow

# Search for errors
aws logs filter-log-events \
  --log-group-name /ecs/visa-mcp-server \
  --filter-pattern "ERROR" \
  --start-time $(date -d '1 hour ago' +%s)000

# Get statistics
aws logs describe-log-streams \
  --log-group-name /ecs/visa-mcp-server
```

### Key Metrics to Monitor

```
- Request count per tool
- Response time per tool
- Error rate by tool
- Payment success rate
- Device attestation success rate
```

### Setting Up Alarms

```bash
# Create alarm for high error rate
aws cloudwatch put-metric-alarm \
  --alarm-name visa-mcp-error-rate \
  --alarm-description "Alarm when Visa MCP error rate exceeds 5%" \
  --metric-name ErrorRate \
  --namespace VisaMCP \
  --statistic Average \
  --period 300 \
  --threshold 5 \
  --comparison-operator GreaterThanThreshold \
  --evaluation-periods 2
```

### Log Pattern Examples

```
# Successful token retrieval
"X-PAY-TOKEN generated successfully"

# Device attestation success
"Device Attestation Authenticate completed successfully"

# Payment credential generation
"VIC Get Payment Credentials completed successfully"

# Errors to watch
"ERROR in visa_onboard_card"
"TOKEN PROVISIONING FAILED"
"DEVICE ATTESTATION AUTHENTICATE - REQUEST FAILED"
```

---

## Troubleshooting

### Common Issues

#### Issue 1: Secrets Manager Access Denied

**Error**: `AccessDeniedException: User is not authorized to perform: secretsmanager:GetSecretValue`

**Causes**:
- IAM role doesn't have Secrets Manager permissions
- Secret doesn't exist in Secrets Manager
- Secret name is incorrect

**Solution**:

```bash
# Check IAM permissions
aws iam get-user-policy --user-name your-user --policy-name your-policy

# Verify secret exists
aws secretsmanager get-secret-value --secret-id visa/api-key

# Create missing secret if needed
aws secretsmanager create-secret --name visa/api-key --secret-string "value"
```

#### Issue 2: Invalid Secure Token

**Error**: `visa_device_attestation returned {"success": false, "error": "Invalid secure token"}`

**Causes**:
- Token expired (typically 10 minutes)
- Token malformed or truncated
- Visa OAuth API unreachable

**Solution**:

```python
# Implement token refresh
def get_fresh_token():
    result = visa_get_secure_token()
    if result["success"]:
        return result["secureToken"]
    else:
        # Log and retry with backoff
        time.sleep(2)
        return get_fresh_token()
```

#### Issue 3: Card Onboarding Fails

**Error**: `visa_onboard_card returned {"success": false, "error": "Failed to get vPanEnrollmentID from enrollment response"}`

**Causes**:
- Invalid card number (fails Luhn check)
- Card already enrolled by another account
- Visa API rate limiting
- Missing encryption secrets

**Solution**:

```bash
# Verify encryption secrets exist
aws secretsmanager get-secret-value --secret-id visa/encryption-api-key
aws secretsmanager get-secret-value --secret-id visa/encryption-shared-secret

# Test card number validity
python -c "
import sys
def luhn(n):
    return sum(map(int, n[::2])) + sum(map(int, n[1::2])) % 2 * 9 % 10
# Should return 0 for valid card
print('Valid' if luhn('4111111111111111') == 0 else 'Invalid')
"
```

#### Issue 4: Device Attestation Returns Empty Identifier

**Error**: `"identifier": null` in device attestation response

**Causes**:
- x_request_id doesn't match enrollment session
- Browser data is malformed
- Visa API didn't return proper response

**Solution**:

```python
# Ensure x_request_id continuity
onboard_result = visa_onboard_card(...)
session_id = onboard_result["x_request_id"]

# Use same session_id in all subsequent calls
attestation_result = visa_device_attestation(
    x_request_id=session_id,  # Must match onboarding
    ...
)

# Verify browser_data is valid if provided
browser_data = {
    "userAgent": "Mozilla/5.0",
    "browserPlatform": "Web Platform",
    "ipAddress": "192.168.1.1"
}
```

#### Issue 5: OTP Validation Fails

**Error**: `visa_validate_otp returned {"success": false, "error": "Invalid OTP"}`

**Causes**:
- OTP expired (typically 10 minutes)
- Wrong OTP entered
- OTP already used
- Too many failed attempts

**Solution**:

```bash
# Check OTP validity window
# Most Visa implementations allow 3-5 attempts within 10 minutes

# Implement proper retry logic
max_attempts = 3
for attempt in range(max_attempts):
    otp = input(f"Enter OTP (attempt {attempt+1}/{max_attempts}): ")
    result = visa_validate_otp(provisioned_token_id, otp, ...)
    if result["success"]:
        break
    elif attempt == max_attempts - 1:
        raise Exception("Max OTP validation attempts exceeded")
    else:
        print(f"Invalid OTP, try again")
        time.sleep(2)
```

#### Issue 6: VIC Enrollment Fails

**Error**: `visa_vic_enroll_card returned {"success": false, "error": "Response missing 'encData' field"}`

**Causes**:
- VIC private key not available in Secrets Manager
- Server certificate corrupted
- VIC API returns error response

**Solution**:

```bash
# Verify certificates are valid
aws secretsmanager get-secret-value --secret-id visa/server-mle-cert | \
  jq '.SecretString' | \
  openssl x509 -text -noout

# Check if PEM format is correct
aws secretsmanager get-secret-value --secret-id visa/mle-private-cert | \
  jq '.SecretString' | grep "BEGIN PRIVATE KEY"
```

#### Issue 7: Payment Credentials Returns Invalid JWT

**Error**: `visa_vic_payment_credentials returned signedPayload but can't decode JWT`

**Causes**:
- JWT signature doesn't match
- JWT expired
- Cryptogram extraction failed

**Solution**:

```python
# Decode JWT safely
import json
import base64

def decode_jwt(token):
    try:
        parts = token.split('.')
        if len(parts) != 3:
            raise ValueError("Invalid JWT structure")

        # Decode payload (second part)
        payload = parts[1]
        # Add padding if needed
        padding = 4 - len(payload) % 4
        if padding != 4:
            payload += '=' * padding

        decoded = base64.urlsafe_b64decode(payload)
        return json.loads(decoded)
    except Exception as e:
        print(f"Failed to decode JWT: {e}")
        return None

# Extract cryptogram
jwt_payload = decode_jwt(signed_payload)
if jwt_payload and "dynamicData" in jwt_payload:
    cryptogram = jwt_payload["dynamicData"][0]["dynamicDataValue"]
    print(f"Cryptogram: {cryptogram}")
```

### Debug Logging

Enable detailed logging for troubleshooting:

```bash
# Set environment variable
export LOG_LEVEL=DEBUG

# Or modify logging in code
import logging
logging.basicConfig(level=logging.DEBUG)

# Run server with debug logging
python server.py
```

View detailed logs:

```bash
# All log entries
aws logs tail /ecs/visa-mcp-server --follow

# Only errors
aws logs filter-log-events \
  --log-group-name /ecs/visa-mcp-server \
  --filter-pattern "[ERROR]" \
  --follow
```

### Health Check Script

```bash
#!/bin/bash
# check_visa_health.sh

SERVER_URL="http://localhost:5000"

echo "Checking Visa MCP Server Health..."

# Check server is running
response=$(curl -s -w "\n%{http_code}" "$SERVER_URL/health")
http_code=$(echo "$response" | tail -n1)
body=$(echo "$response" | head -n-1)

if [ "$http_code" = "200" ]; then
    echo "✓ Server is healthy"
    echo "Response: $body"
else
    echo "✗ Server health check failed (HTTP $http_code)"
    echo "Response: $body"
    exit 1
fi

# Check Secrets Manager access
echo ""
echo "Checking Secrets Manager access..."
if aws secretsmanager get-secret-value --secret-id visa/api-key &>/dev/null; then
    echo "✓ Can access Secrets Manager"
else
    echo "✗ Cannot access Secrets Manager"
    exit 1
fi

echo ""
echo "All checks passed!"
```

---

## Performance Tuning

### Concurrency

Configure task concurrency in CDK:

```typescript
// lib/visa-stack.ts
desiredCount: 3,  // Number of containers
cpu: '512',
memory: '1024',
```

### Timeout Configuration

Adjust timeouts based on your needs:

```python
# In tools.py
VISA_API_TIMEOUT = 300  # seconds
requests.post(url, timeout=VISA_API_TIMEOUT)
```

### Caching Strategy

Implement token caching to reduce API calls:

```python
import time
from functools import wraps

_token_cache = {}
TOKEN_CACHE_TTL = 600  # 10 minutes

def cache_secure_token(func):
    @wraps(func)
    def wrapper(*args, **kwargs):
        now = time.time()
        if "token" in _token_cache:
            token, timestamp = _token_cache["token"]
            if now - timestamp < TOKEN_CACHE_TTL:
                return token

        result = func(*args, **kwargs)
        if result["success"]:
            _token_cache["token"] = (result["secureToken"], now)

        return result

    return wrapper

@cache_secure_token
def get_secure_token_cached(clientAppId="VICTestAccountTR"):
    return visa_get_secure_token(clientAppId)
```

---

## Security Best Practices

1. **Rotate Secrets Regularly**
   ```bash
   # Rotate API key every 90 days
   aws secretsmanager rotate-secret \
     --secret-id visa/api-key \
     --rotation-lambda-arn arn:aws:lambda:...
   ```

2. **Use VPC Endpoints**
   ```bash
   # Create VPC endpoint for Secrets Manager
   aws ec2 create-vpc-endpoint \
     --vpc-id vpc-xxx \
     --service-name com.amazonaws.us-east-1.secretsmanager
   ```

3. **Enable VPC Flow Logs**
   ```bash
   # Monitor network traffic
   aws ec2 create-flow-logs \
     --resource-type NetworkInterface \
     --traffic-type ALL
   ```

4. **Implement Request Signing**
   - All Visa API calls use HMAC-SHA256
   - Verify X-PAY-TOKEN in all responses

5. **Audit API Calls**
   ```bash
   # Enable CloudTrail
   aws cloudtrail start-logging \
     --name visa-mcp-trail
   ```

---

## Disaster Recovery

### Backup Strategy

```bash
# Backup Secrets Manager
aws secretsmanager describe-secret --secret-id visa/api-key

# Export secrets to secure storage (encrypted)
aws secretsmanager get-secret-value --secret-id visa/api-key | \
  gpg --encrypt --recipient your-key-id > visa-secrets-backup.gpg
```

### Failover

```bash
# Deploy to secondary region
cdk deploy VisaStack \
  --context region=us-west-2

# Update DNS to point to secondary
aws route53 change-resource-record-sets \
  --hosted-zone-id Z123 \
  --change-batch file://failover.json
```

### Rollback

```bash
# Rollback to previous version
cdk deploy VisaStack \
  --context version=previous

# Or manually delete stack and redeploy
aws cloudformation delete-stack --stack-name VisaStack
cdk deploy VisaStack
```

---

## Support & Resources

### Getting Help

1. Check logs: `aws logs tail /ecs/visa-mcp-server --follow`
2. Review tool reference: `docs/visa-mcp-tools-reference.md`
3. Check integration guide (this file)
4. Review migration notes: `docs/visa-flask-to-mcp-migration.md`

### Visa Documentation

- [Visa Developer Portal](https://developer.visa.com/)
- [VTS API Documentation](https://developer.visa.com/guides/vts)
- [VIC API Documentation](https://developer.visa.com/guides/vic)

### AWS Documentation

- [Secrets Manager Guide](https://docs.aws.amazon.com/secretsmanager/)
- [ECS Task Definitions](https://docs.aws.amazon.com/AmazonECS/latest/developerguide/task_definitions.html)
- [CDK Documentation](https://docs.aws.amazon.com/cdk/latest/guide/)

