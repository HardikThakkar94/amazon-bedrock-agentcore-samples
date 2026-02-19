"""
Visa Subagent

A subagent that handles Visa payment operations by connecting to Visa tools
via the gateway. Exposed as a tool for the main supervisor agent.
"""

import os
import logging
from strands import Agent, tool
from strands.models import BedrockModel
from strands.tools.mcp import MCPClient

from gateway_client import get_gateway_client

logger = logging.getLogger(__name__)

REGION = os.getenv("AWS_REGION", "us-east-1")

# =============================================================================
# VISA AGENT SYSTEM PROMPT
# =============================================================================

VISA_AGENT_PROMPT = """
You are a payment specialist designed to handle secure card onboarding and payment processing using Visa's Token Service (VTS) and Visa In-App Commerce (VIC).

Your primary responsibilities include:
1. Securely onboarding payment cards using Visa tokenization
2. Managing device attestation and security
3. Processing payments through Visa's secure payment flows
4. Handling OTP validation and step-up authentication

You have access to the following Visa tools:
- `visa_get_secure_token`: Get OAuth secure token for authentication (clientAppId)
- `visa_onboard_card`: Onboard a card to Visa Token Service (email, accountNumber, cvv2, expirationDate, clientAppId, clientWalletAccountId)
- `visa_device_attestation`: Device security attestation - AUTHENTICATE or REGISTER (email, secureToken, step, x_request_id, browser_data)
- `visa_device_binding`: Bind device with FIDO passkey (secureToken, provisionedTokenId, x_request_id, fidoRegistrationData, browser_data)
- `visa_step_up`: Initiate OTP step-up authentication (provisionedTokenId, x_request_id)
- `visa_validate_otp`: Validate OTP code (provisionedTokenId, otp, x_request_id)
- `visa_complete_passkey`: Parse FIDO passkey response (fidoBlob)
- `visa_vic_enroll_card`: Enroll card for VIC payments (email, accountNumber, cvv2, expirationDate)
- `visa_vic_initiate_purchase`: Create payment mandate (provisionedTokenId, amount, currencyCode, merchantInfo)
- `visa_vic_payment_credentials`: Get payment cryptogram (instructionId, x_request_id)

IMPORTANT GUIDELINES:

1. **Card Onboarding Flow** (Standard):
   - Get secure token: visa_get_secure_token()
   - Onboard card: visa_onboard_card() → returns vProvisionedTokenID
   - Return the token to the supervisor agent to save to user profile

2. **Device Attestation Flow** (Optional - for enhanced security):
   - Step 1: visa_device_attestation(step="AUTHENTICATE") → returns identifier
   - Step 2: visa_device_attestation(step="REGISTER") → registers device
   - Step 3: visa_device_binding() → binds FIDO passkey

3. **OTP Validation Flow** (When required):
   - Initiate: visa_step_up() → triggers OTP
   - Validate: visa_validate_otp() → confirms OTP

4. **VIC Payment Flow** (For purchases):
   - Enroll: visa_vic_enroll_card() → one-time enrollment
   - Purchase: visa_vic_initiate_purchase() → creates mandate
   - Credentials: visa_vic_payment_credentials() → gets cryptogram

5. **Session Management**:
   - Always preserve x_request_id across related calls in a flow
   - Pass the same x_request_id from onboarding through attestation/binding

RESPONSE FORMAT:
- Always return structured data with success status
- Include vProvisionedTokenID when onboarding succeeds
- Include error messages when operations fail
- Preserve raw_response for debugging

SECURITY NOTES:
- Never log or expose full card numbers (PAN)
- Always use tokenized identifiers (vProvisionedTokenID)
- Browser data is optional for server-side flows
- x_request_id ties together a session's operations

Your goal is to provide secure, compliant payment processing through Visa's infrastructure.
"""


# =============================================================================
# GATEWAY CLIENT FOR VISA TOOLS
# =============================================================================


def get_visa_tools_client() -> MCPClient:
    """Get MCPClient filtered for Visa tools only."""
    return get_gateway_client("^visatools___")


# =============================================================================
# BEDROCK MODEL
# =============================================================================

bedrock_model = BedrockModel(
    model_id="us.anthropic.claude-sonnet-4-20250514-v1:0",
    region_name=REGION,
    temperature=0.1,  # Low temperature for precise payment operations
)


# =============================================================================
# VISA SUBAGENT TOOL
# =============================================================================


@tool
async def visa_payment_assistant(query: str, user_id: str = "", session_id: str = ""):
    """
    Process Visa payment and card onboarding queries using specialized Visa tools.

    AVAILABLE TOOLS:
    - visa_get_secure_token: Get OAuth token (clientAppId)
    - visa_onboard_card: Onboard card (email, accountNumber, cvv2, expirationDate)
    - visa_device_attestation: Device security (email, secureToken, step, x_request_id)
    - visa_device_binding: Bind device (secureToken, provisionedTokenId, x_request_id, fidoRegistrationData)
    - visa_step_up: Start OTP (provisionedTokenId, x_request_id)
    - visa_validate_otp: Validate OTP (provisionedTokenId, otp, x_request_id)
    - visa_complete_passkey: Parse FIDO response (fidoBlob)
    - visa_vic_enroll_card: VIC enrollment (email, accountNumber, cvv2, expirationDate)
    - visa_vic_initiate_purchase: Create payment mandate (provisionedTokenId, amount, currencyCode)
    - visa_vic_payment_credentials: Get cryptogram (instructionId, x_request_id)

    ROUTE HERE FOR:
    - Card onboarding: "Add payment card 4111111111111111 exp 12/25 cvv 123"
    - Device security: "Perform device attestation for user@example.com"
    - OTP validation: "Validate OTP 123456 for token vptoken_abc"
    - Payment processing: "Process payment of $50 for token vptoken_xyz"

    IMPORTANT: Include all required fields when available:
    - Card details: PAN, expiration (MM/YY), CVV
    - User email for tokenization
    - x_request_id for session continuity

    Args:
        query: The payment/card request with as much detail as possible.
        user_id: User identifier for personalization.
        session_id: Session identifier for context.

    Returns:
        Payment processing results, token IDs, or error messages.
        Returns vProvisionedTokenID on successful card onboarding.
    """
    try:
        logger.info(f"Visa subagent (async) processing: {query[:100]}...")

        visa_client = get_visa_tools_client()

        agent = Agent(
            name="visa_agent",
            model=bedrock_model,
            tools=[visa_client],
            system_prompt=VISA_AGENT_PROMPT,
            trace_attributes={
                "user.id": user_id,
                "session.id": session_id,
                "agent.type": "visa_subagent",
            },
        )

        result = ""
        async for event in agent.stream_async(query):
            if "data" in event:
                yield {"data": event["data"]}
            if "current_tool_use" in event:
                yield {"current_tool_use": event["current_tool_use"]}
            if "result" in event:
                result = str(event["result"])

        yield {"result": result}

    except Exception as e:
        logger.error(f"Visa subagent async error: {e}", exc_info=True)
        yield {"error": str(e)}
