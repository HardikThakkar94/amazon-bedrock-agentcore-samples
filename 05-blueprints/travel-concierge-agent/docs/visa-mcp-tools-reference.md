# Visa MCP Tools Reference

Complete documentation of all 10 Visa payment tools available in the MCP server.

## Overview

The Visa MCP Server exposes 10 tools that implement the complete Visa payment flow from card onboarding through payment authorization. These tools integrate with Visa's Token Service (VTS) and Visa In-Commerce (VIC) APIs for secure, tokenized payments.

### Tool Categories

- **Tokenization & Onboarding** (2 tools): Secure token retrieval and card enrollment
- **Device Security** (4 tools): Device attestation, binding, and step-up authentication
- **VIC Payment Flow** (3 tools): Card enrollment with VIC, purchase instructions, and credential retrieval
- **Passkey Completion** (1 tool): Parse FIDO passkey authentication responses

---

## Tool 1: `visa_get_secure_token`

Retrieve a Visa OAuth secure token for authentication sessions. This token is required for all subsequent operations.

### Purpose
Initiates a secure authentication session with Visa's OAuth API, bypassing the iframe completely. Returns tokens needed for card onboarding and device attestation.

### Parameters

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| `clientAppId` | string | No | "VICTestAccountTR" | Your Visa client application ID |

### Returns

```python
{
    "success": bool,
    "secureToken": str,        # OAuth token for session
    "requestID": str,          # Device ID (session identifier)
    "proof_verifier": str,     # PKCE verifier for token validation
    "device_fingerprint": str, # Unique device identifier
    "error": str              # Only if success=false
}
```

### Error Cases

- Invalid or missing API key in Secrets Manager
- Network timeout connecting to Visa OAuth API
- Malformed response from Visa servers

### Example Usage

```python
# Get secure token to start a session
result = visa_get_secure_token(clientAppId="VICTestAccountTR")

if result["success"]:
    secure_token = result["secureToken"]
    request_id = result["requestID"]
    # Use these for subsequent operations
else:
    print(f"Error: {result['error']}")
```

### Notes

- Creates a new OAuth session each time it's called
- Session is valid for a limited time (check Visa API docs for timeout)
- Token should be stored and reused for the same user's session
- Device fingerprint is generated uniquely for each session

---

## Tool 2: `visa_onboard_card`

Enroll a card with Visa Token Service and provision a token. This combines PAN enrollment and token provisioning into a single operation.

### Purpose
Takes card credentials and returns a provisioned token ID that represents the card in the Visa system. This is the foundation for all payment transactions.

### Parameters

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| `email` | string | Yes | - | User's email address for hashing |
| `accountNumber` | string | Yes | - | Card number (PAN, 16 digits) |
| `cvv2` | string | Yes | - | Card CVV2 code (3-4 digits) |
| `expirationDate` | string | Yes | - | Card expiration (format: "YYYY-MM") |
| `clientAppId` | string | No | "VICTestAccountTR" | Visa application ID |
| `clientWalletAccountId` | string | No | "40010062596" | Wallet account identifier |

### Returns

```python
{
    "success": bool,
    "vProvisionedTokenID": str,    # Token ID for payment transactions
    "encTokenInfo": str,           # Encrypted token details (JWE format)
    "x_request_id": str,           # Session ID for continuity
    "raw_response": dict,          # Full Visa API response
    "error": str                   # Only if success=false
}
```

### Error Cases

- Invalid card data (wrong CVV, expiration format)
- Card number fails Luhn validation
- Visa API rejects card (fraud, expired, etc.)
- Secrets Manager cannot retrieve encryption keys

### Example Usage

```python
# Onboard a test card
result = visa_onboard_card(
    email="user@example.com",
    accountNumber="4111111111111111",
    cvv2="123",
    expirationDate="2025-12",
    clientAppId="VICTestAccountTR"
)

if result["success"]:
    token_id = result["vProvisionedTokenID"]
    session_id = result["x_request_id"]
    print(f"Token ID: {token_id}")
    # Use token_id for subsequent operations
else:
    print(f"Onboarding failed: {result['error']}")
```

### Notes

- Performs two API calls internally: enrollment (enroll_pan) and provisioning (provision_token)
- The returned `x_request_id` must be preserved for device attestation later
- Card data is encrypted before transmission using symmetric encryption
- Email is hashed using SHA-256 for privacy

---

## Tool 3: `visa_device_attestation`

Verify device identity using AUTHENTICATE or REGISTER steps. Used for security validation before payments.

### Purpose
Establishes device identity through Visa's attestation mechanism. The AUTHENTICATE step verifies a known device; REGISTER step registers a new device for passkey-based authentication.

### Parameters

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| `email` | string | Yes | - | User email address |
| `secureToken` | string | Yes | - | Token from visa_get_secure_token |
| `provisionedTokenId` | string | Yes | - | Token ID from visa_onboard_card |
| `clientAppId` | string | Yes | - | Visa application ID |
| `x_request_id` | string | Yes | - | Session ID from onboarding |
| `step` | string | No | "AUTHENTICATE" | "AUTHENTICATE" or "REGISTER" |
| `transactionAmount` | string | No | "567.89" | Transaction amount for context |

### Returns

```python
{
    "success": bool,
    "step": str,                  # Which attestation step was performed
    "identifier": str,            # Attestation identifier for subsequent steps
    "client_reference_id": str,   # Generated transaction reference
    "raw_response": dict,         # Full Visa API response
    "error": str                  # Only if success=false
}
```

### Error Cases

- Invalid secure token (expired or malformed)
- Token ID doesn't exist in Visa system
- Device data is invalid or missing
- Browser data is incomplete

### Example Usage

```python
# Authenticate the device before payment
result = visa_device_attestation(
    email="user@example.com",
    secureToken=secure_token,
    provisionedTokenId=token_id,
    clientAppId="VICTestAccountTR",
    x_request_id=session_id,
    step="AUTHENTICATE",
    transactionAmount="567.89"
)

if result["success"]:
    identifier = result["identifier"]
    print(f"Device authenticated: {identifier}")
else:
    print(f"Device attestation failed: {result['error']}")
```

### Browser Data Strategy

The tool provides minimal browser data (user agent, platform, IP) which is valid because:
- Visa's iframe session already established device context
- Server-side calls can use generic browser data
- Visa API validates device context through tokenization flow, not browser data alone
- For iframe-based flows, real browser data is captured by the iframe

---

## Tool 4: `visa_device_binding`

Bind device for FIDO/passkey authentication. Enables passwordless, biometric-based authentication.

### Purpose
Establishes a device binding that allows future FIDO2/passkey authentication without card details. Creates a cryptographic binding between the device and the user's account.

### Parameters

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| `secureToken` | string | Yes | - | Token from visa_get_secure_token |
| `email` | string | Yes | - | User email address |
| `provisionedTokenId` | string | Yes | - | Token ID from visa_onboard_card |
| `clientAppId` | string | Yes | - | Visa application ID |
| `x_request_id` | string | Yes | - | Session ID from onboarding |

### Returns

```python
{
    "success": bool,
    "client_reference_id": str,   # Generated reference for this binding
    "raw_response": dict,         # Full Visa API response
    "error": str                  # Only if success=false
}
```

### Error Cases

- Device attestation not completed first
- Email hash cannot be generated
- Visa API rejects device binding request
- Session has expired

### Example Usage

```python
# Bind device for future passkey auth
result = visa_device_binding(
    secureToken=secure_token,
    email="user@example.com",
    provisionedTokenId=token_id,
    clientAppId="VICTestAccountTR",
    x_request_id=session_id
)

if result["success"]:
    print("Device bound successfully for passkey auth")
else:
    print(f"Device binding failed: {result['error']}")
```

### Notes

- Must be performed after device attestation
- Creates cryptographic binding for FIDO2 authentication
- Enables biometric login on supported devices
- One device per account is typical, but multiple devices can be bound

---

## Tool 5: `visa_step_up`

Initiate step-up authentication, typically OTP-based verification. Used for additional security challenges.

### Purpose
Selects and initiates a step-up authentication method (typically OTP sent via SMS/email). Used for high-security transactions or passwordless authentication flows.

### Parameters

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| `provisionedTokenId` | string | Yes | - | Token ID from visa_onboard_card |
| `identifier` | string | Yes | - | Identifier from device attestation |
| `clientAppId` | string | Yes | - | Visa application ID |
| `x_request_id` | string | Yes | - | Session ID from onboarding |

### Returns

```python
{
    "success": bool,
    "client_reference_id": str,   # Reference for OTP validation
    "raw_response": dict,         # Contains OTP delivery method info
    "error": str                  # Only if success=false
}
```

### Error Cases

- Invalid identifier from attestation
- User has no registered contact method for OTP
- Too many step-up attempts (rate limiting)
- Session expired

### Example Usage

```python
# Initiate OTP-based step-up
result = visa_step_up(
    provisionedTokenId=token_id,
    identifier=attestation_identifier,
    clientAppId="VICTestAccountTR",
    x_request_id=session_id
)

if result["success"]:
    ref_id = result["client_reference_id"]
    print(f"OTP initiated, reference: {ref_id}")
    # User receives OTP code via SMS/email
else:
    print(f"Step-up failed: {result['error']}")
```

### Notes

- Must be preceded by device attestation
- Returns reference ID to use with visa_validate_otp
- OTP is typically valid for 10 minutes
- Multiple attempts may be rate-limited by Visa

---

## Tool 6: `visa_validate_otp`

Validate OTP code received by user. Completes the step-up authentication.

### Purpose
Verifies the one-time password (OTP) sent to the user. Completes step-up authentication and allows transaction to proceed.

### Parameters

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| `provisionedTokenId` | string | Yes | - | Token ID from visa_onboard_card |
| `otpValue` | string | Yes | - | OTP code received by user (typically 6 digits) |
| `clientAppId` | string | Yes | - | Visa application ID |
| `x_request_id` | string | Yes | - | Session ID from onboarding |

### Returns

```python
{
    "success": bool,
    "client_reference_id": str,   # Reference for this validation attempt
    "raw_response": dict,         # Full Visa API response
    "error": str                  # Only if success=false
}
```

### Error Cases

- Invalid OTP (wrong code)
- OTP expired (too much time elapsed)
- Too many failed validation attempts
- Token ID doesn't match original step-up

### Example Usage

```python
# Validate OTP from user input
user_otp = input("Enter OTP code: ")

result = visa_validate_otp(
    provisionedTokenId=token_id,
    otpValue=user_otp,
    clientAppId="VICTestAccountTR",
    x_request_id=session_id
)

if result["success"]:
    print("OTP validated successfully")
    # Transaction can now proceed
else:
    print(f"OTP validation failed: {result['error']}")
```

### Notes

- Must be called after visa_step_up with same session
- OTP is case-insensitive (if alpha characters)
- Typically has 3-5 retry attempts before lockout
- Consider rate limiting on client side to prevent brute force

---

## Tool 7: `visa_complete_passkey`

Parse FIDO passkey authentication response from Visa iframe.

### Purpose
Extracts authentication result (code and hint) from the URL-encoded FIDO blob returned by Visa's passkey iframe. Bridges browser-side FIDO authentication with server-side payment processing.

### Parameters

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| `fidoBlob` | string | Yes | - | URL-encoded FIDO response from iframe |

### Returns

```python
{
    "success": bool,
    "code": str,               # Authentication code for payment
    "hint": str,              # Additional authentication hint (may be null)
    "raw_parsed": dict,       # All parsed query parameters
    "error": str              # Only if success=false
}
```

### Error Cases

- Malformed URL encoding
- Missing 'code' parameter in response
- Invalid format from iframe (shouldn't happen with valid iframe)

### Example Usage

```python
# Process FIDO response from iframe
fido_blob_from_iframe = "code=xyz123&hint=face_recognition"

result = visa_complete_passkey(fidoBlob=fido_blob_from_iframe)

if result["success"]:
    auth_code = result["code"]
    print(f"FIDO authentication code: {auth_code}")
    # Use code in VIC payment flow
else:
    print(f"FIDO parsing failed: {result['error']}")
```

### Browser Data Captured

This tool extracts browser-captured data from the iframe without needing additional browser parameters because:
- The iframe handles all browser context collection
- FIDO authentication happens in browser security context
- The code returned proves browser-side verification succeeded
- Server validates code signature (handled by Visa backend)

---

## Tool 8: `visa_vic_enroll_card`

Enroll provisioned token with Visa In-Commerce (VIC) for AI agent payments.

### Purpose
Registers the card token with VIC system, enabling autonomous payment instructions. This prepares the card for repeated use in AI agent payment scenarios without requiring repeated card entry.

### Parameters

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| `email` | string | Yes | - | User email for consumer identity |
| `provisionedTokenId` | string | Yes | - | Token ID from visa_onboard_card |
| `clientAppId` | string | Yes | - | Visa application ID |

### Returns

```python
{
    "success": bool,
    "clientReferenceId": str,    # VIC enrollment reference
    "status": str,               # Enrollment status ("SUCCESS", etc.)
    "client_device_id": str,     # Generated device ID for this enrollment
    "consumer_id": str,          # VIC consumer ID for payment instructions
    "raw_response": dict,        # Full Visa API response
    "error": str                 # Only if success=false
}
```

### Error Cases

- Token ID not found in VIC system
- Email format invalid or missing
- VIC enrollment quota exceeded
- Encryption certificate not available in Secrets Manager

### Example Usage

```python
# Enroll card with VIC for AI agent payments
result = visa_vic_enroll_card(
    email="user@example.com",
    provisionedTokenId=token_id,
    clientAppId="VICTestAccountTR"
)

if result["success"]:
    consumer_id = result["consumer_id"]
    client_device_id = result["client_device_id"]
    print(f"Card enrolled in VIC - Consumer ID: {consumer_id}")
    # Use for payment instructions
else:
    print(f"VIC enrollment failed: {result['error']}")
```

### Notes

- Creates unique consumer_id and client_device_id for session continuity
- Uses RSA encryption (not symmetric) with VIC server certificate
- Device data includes mock device info (iPhone, Apple) - can be customized
- Enrollment is specific to this application/consumer combination

---

## Tool 9: `visa_vic_initiate_purchase`

Initiate VIC purchase instructions with passkey assurance data. Creates a payment mandate for AI agent execution.

### Purpose
Creates a payment mandate that authorizes AI agents to make purchases up to specified limits. Includes device attestation and passkey verification proof in the mandate.

### Parameters

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| `provisionedTokenId` | string | Yes | - | Token ID from visa_onboard_card |
| `consumerId` | string | Yes | - | Consumer ID from visa_vic_enroll_card |
| `clientAppId` | string | Yes | - | Visa application ID |
| `consumerRequest` | string | Yes | - | Purchase intent description (max 150 chars) |
| `clientReferenceId` | string | Yes | - | Reference ID from enrollment |
| `clientDeviceId` | string | Yes | - | Device ID from enrollment |
| `authIdentifier` | string | Yes | - | Identifier from device attestation |
| `dfpSessionId` | string | Yes | - | DFP session ID from Visa iframe |
| `iframeAuthFidoBlob` | string | Yes | - | FIDO assertion code from passkey auth |
| `transactionAmount` | string | No | "444.44" | Max transaction amount (format: "000.00") |

### Returns

```python
{
    "success": bool,
    "instructionId": str,        # ID for retrieving payment credentials
    "clientReferenceId": str,    # Same as input reference
    "status": str,               # Instruction status ("SUCCESS", etc.)
    "mandate_id": str,           # Generated mandate ID
    "raw_response": dict,        # Full Visa API response
    "error": str                 # Only if success=false
}
```

### Error Cases

- Consumer ID not found in VIC system
- Device attestation identifier invalid
- FIDO blob malformed or expired
- DFP session ID doesn't match device attestation
- Transaction amount exceeds VIC limits
- Consumer request exceeds 150 character limit

### Example Usage

```python
# Create payment mandate for AI agent
result = visa_vic_initiate_purchase(
    provisionedTokenId=token_id,
    consumerId=consumer_id,
    clientAppId="VICTestAccountTR",
    consumerRequest="Buy groceries",
    clientReferenceId=ref_id,
    clientDeviceId=device_id,
    authIdentifier=attestation_id,
    dfpSessionId=dfp_session_id,
    iframeAuthFidoBlob=fido_code,
    transactionAmount="444.44"
)

if result["success"]:
    instruction_id = result["instructionId"]
    print(f"Purchase mandate created: {instruction_id}")
else:
    print(f"Purchase initiation failed: {result['error']}")
```

### Notes

- Includes multiple assurance levels: device attestation + passkey verification
- Consumer request is truncated to 150 characters internally
- Transaction amount is validated to 2 decimal places
- Mandate is valid for 10 days (864000 seconds)
- Mandate includes merchant category code (5411) for groceries

---

## Tool 10: `visa_vic_payment_credentials`

Retrieve payment credentials (cryptogram) for transaction authorization.

### Purpose
Gets the encrypted payment credentials (cryptogram) needed to complete an actual payment transaction. This is the final step before merchant authorization.

### Parameters

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| `instructionId` | string | Yes | - | Instruction ID from visa_vic_initiate_purchase |
| `provisionedTokenId` | string | Yes | - | Token ID from visa_onboard_card |
| `clientAppId` | string | Yes | - | Visa application ID |
| `clientReferenceId` | string | Yes | - | Reference ID from enrollment |
| `merchantUrl` | string | Yes | - | Merchant website URL |
| `merchantName` | string | Yes | - | Merchant display name |
| `transactionAmount` | string | Yes | - | Transaction amount (format: "000.00") |

### Returns

```python
{
    "success": bool,
    "signedPayload": str,        # JWT with cryptogram (send to merchant)
    "instructionId": str,        # Same as input instruction ID
    "status": str,               # Credential status ("SUCCESS", etc.)
    "raw_response": dict,        # Full Visa API response
    "error": str                 # Only if success=false
}
```

### Error Cases

- Instruction ID not found or expired
- Transaction amount exceeds mandate limit
- Merchant details don't match instruction
- Cryptogram generation failed
- Signature timestamp mismatch

### Example Usage

```python
# Get payment credentials for merchant
result = visa_vic_payment_credentials(
    instructionId=instruction_id,
    provisionedTokenId=token_id,
    clientAppId="VICTestAccountTR",
    clientReferenceId=ref_id,
    merchantUrl="https://walmart.com",
    merchantName="Walmart",
    transactionAmount="123.45"
)

if result["success"]:
    cryptogram = result["signedPayload"]
    print(f"Cryptogram retrieved: {cryptogram[:50]}...")
    # Send cryptogram to merchant for authorization
else:
    print(f"Credential retrieval failed: {result['error']}")
```

### Cryptogram Structure

The returned `signedPayload` is a JWT containing:
- **Header**: Signature algorithm (RS256), key ID, timestamp
- **Payload**: Encrypted cryptogram value, transaction details
- **Signature**: Signed by Visa private key (verified by merchant)

The merchant decodes the JWT (without verification if using Visa's public key endpoint) to extract the cryptogram value from the `dynamicData` field.

### Notes

- JWT is valid for single transaction only
- Cryptogram is time-sensitive (typically 15-30 minutes)
- Amount must match mandate specifications
- Merchant URL and name help prevent credential misuse

---

## Error Handling Patterns

### Common Error Response Format

All tools follow the same error pattern:

```python
{
    "success": False,
    "error": "Human-readable error message"
}
```

### Retry Strategy

Implement exponential backoff for transient errors:

```python
import time

def retry_tool_call(tool_func, max_retries=3, *args, **kwargs):
    """Retry a tool call with exponential backoff"""
    for attempt in range(max_retries):
        result = tool_func(*args, **kwargs)
        if result["success"]:
            return result

        # Check if error is retryable (network timeout, etc.)
        if "timeout" in result.get("error", "").lower():
            if attempt < max_retries - 1:
                wait_time = 2 ** attempt
                print(f"Retry attempt {attempt + 1}, waiting {wait_time}s...")
                time.sleep(wait_time)
                continue

        # Non-retryable error
        return result

    return result
```

### Error Classification

| Error Type | Examples | Retry? | Action |
|------------|----------|--------|--------|
| Validation | Invalid email, missing param | No | Fix input and retry |
| Authentication | Invalid token, expired session | No | Restart authentication flow |
| Business Logic | Card declined, insufficient balance | No | User intervention needed |
| Transient | Timeout, temporary service unavailable | Yes | Exponential backoff retry |
| Infrastructure | Missing Secrets Manager access | No | Check AWS IAM and secrets |

---

## Complete Flow Example

Here's a full payment flow combining all tools:

```python
# 1. Get secure token
token_result = visa_get_secure_token(clientAppId="VICTestAccountTR")
secure_token = token_result["secureToken"]
session_id = token_result["x_request_id"]

# 2. Onboard card
card_result = visa_onboard_card(
    email="user@example.com",
    accountNumber="4111111111111111",
    cvv2="123",
    expirationDate="2025-12"
)
token_id = card_result["vProvisionedTokenID"]

# 3. Authenticate device
auth_result = visa_device_attestation(
    email="user@example.com",
    secureToken=secure_token,
    provisionedTokenId=token_id,
    clientAppId="VICTestAccountTR",
    x_request_id=session_id,
    step="AUTHENTICATE"
)
auth_id = auth_result["identifier"]

# 4. Get payment credentials (for direct payment)
# OR continue with VIC flow for AI agent payments...

# 5 (VIC Only). Enroll with VIC
vic_result = visa_vic_enroll_card(
    email="user@example.com",
    provisionedTokenId=token_id,
    clientAppId="VICTestAccountTR"
)
consumer_id = vic_result["consumer_id"]

# 6 (VIC Only). Initiate purchase mandate
mandate_result = visa_vic_initiate_purchase(
    provisionedTokenId=token_id,
    consumerId=consumer_id,
    clientAppId="VICTestAccountTR",
    consumerRequest="Buy apples and oranges",
    clientReferenceId=vic_result["clientReferenceId"],
    clientDeviceId=vic_result["client_device_id"],
    authIdentifier=auth_id,
    dfpSessionId=session_id,
    iframeAuthFidoBlob=fido_code,
    transactionAmount="99.99"
)
instruction_id = mandate_result["instructionId"]

# 7 (VIC Only). Get payment cryptogram
creds_result = visa_vic_payment_credentials(
    instructionId=instruction_id,
    provisionedTokenId=token_id,
    clientAppId="VICTestAccountTR",
    clientReferenceId=vic_result["clientReferenceId"],
    merchantUrl="https://walmart.com",
    merchantName="Walmart",
    transactionAmount="99.99"
)
cryptogram = creds_result["signedPayload"]

# Send cryptogram to merchant for authorization
print(f"Ready to authorize with: {cryptogram[:100]}...")
```

---

## Browser Data Strategy

### Why Minimal Browser Data?

The Visa MCP server uses minimal/generic browser data for several reasons:

1. **Iframe Already Established Context**: When tools are called from the server, the Visa iframe has already collected comprehensive browser data from the actual browser session.

2. **Tokenization Validates Device**: The device identity is validated through:
   - Card tokenization flow (establishes cardholder identity)
   - Device attestation (establishes device identity)
   - FIDO2/passkey binding (establishes cryptographic binding)
   - NOT just browser data alone

3. **Server-Side Calls Are Legitimate**: Payment instructions created server-side (by AI agents) are:
   - Authorized by explicit user mandate
   - Protected by payment limits
   - Validated through device attestation from enrollment
   - Signed with cryptographic keys

4. **Data Privacy**: Generic browser data doesn't leak specific user device details to Visa logs.

### Browser Data Fallback Logic

In `visa/flow.py`, the provision_token function handles both scenarios:

```python
if browser_data:
    # Using real browser data from iframe
    logger.info("✅ Using real browser data from Visa iframe")
    # Extract device fingerprint from user agent
    device_id = hashlib.md5(user_agent.encode()).hexdigest()[:16]
else:
    # Fallback to dummy data when called server-side
    logger.warning("⚠️ No browser data provided - using dummy device data")
    # Generic device profile (iPhone, iOS 16.0)
```

This strategy allows:
- **Browser flows**: Full real browser context with iframe
- **Server flows**: Lightweight dummy data, validated through device attestation
- **Both flows**: Work with Visa's security model

---

## Rate Limiting & Quotas

### Typical Visa API Limits

- Secure token requests: 100/minute
- Card enrollments: 10/day per email
- Device attestations: 50/day per token
- OTP validation attempts: 3-5 failures before temporary lock
- VIC payment instructions: 100/day per consumer

### Recommended Rate Limiting

```python
import time
from collections import defaultdict

class RateLimiter:
    def __init__(self):
        self.request_times = defaultdict(list)
        self.window_seconds = 60

    def check_limit(self, key: str, max_requests: int) -> bool:
        now = time.time()
        cutoff = now - self.window_seconds

        # Remove old requests outside window
        self.request_times[key] = [
            t for t in self.request_times[key] if t > cutoff
        ]

        if len(self.request_times[key]) >= max_requests:
            return False

        self.request_times[key].append(now)
        return True

limiter = RateLimiter()

# Check before calling tool
if not limiter.check_limit("secure_token", max_requests=10):
    raise Exception("Rate limit exceeded for secure_token")
```

---

## Testing Tools Locally

### Prerequisites

- AWS credentials configured with Secrets Manager access
- Visa test account credentials in Secrets Manager
- Test card numbers from Visa documentation

### Example Test Script

```python
from mcp.client import Client

# Connect to MCP server
client = Client(host="localhost", port=5000)

# Test secure token
print("Testing visa_get_secure_token...")
token_result = client.call_tool("visa_get_secure_token", {
    "clientAppId": "VICTestAccountTR"
})
print(f"Result: {token_result}")

# Test with different parameters
print("\nTesting visa_onboard_card...")
card_result = client.call_tool("visa_onboard_card", {
    "email": "test@example.com",
    "accountNumber": "4111111111111111",
    "cvv2": "123",
    "expirationDate": "2025-12"
})
print(f"Result: {card_result}")
```

---

## Security Considerations

1. **Never log sensitive data**: Secure tokens, card numbers, OTPs
2. **Validate x_request_id continuity**: Ensures session integrity
3. **Use HTTPS only**: All Visa API calls must use TLS 1.2+
4. **Rotate credentials**: Regularly rotate API keys in Secrets Manager
5. **Implement rate limiting**: Prevent brute force OTP attacks
6. **Timeout handling**: Set appropriate timeouts (default 300s) for long-running calls
7. **Error messages**: Don't expose Visa API errors directly to users

---

## Visa Test Credentials

### Test Card Numbers

| Card Type | PAN | CVV | Exp Date |
|-----------|-----|-----|----------|
| Visa | 4111111111111111 | 123 | 2025-12 |
| Visa (3D) | 4012888888881881 | 123 | 2025-12 |
| Visa (Decline) | 4111111111111112 | 123 | 2025-12 |

### Test Email

Use any email for testing: `test@example.com`, `user@test.com`, etc.

### Default Client App ID

Most examples use: `VICTestAccountTR` (Test Account)

---

## Additional Resources

- [Visa VTS Documentation](https://developer.visa.com/)
- [MCP Protocol Specification](https://modelcontextprotocol.io/)
- [AWS Secrets Manager Guide](https://docs.aws.amazon.com/secretsmanager/)
- [FIDO2/WebAuthn Standards](https://www.w3.org/TR/webauthn-2/)
