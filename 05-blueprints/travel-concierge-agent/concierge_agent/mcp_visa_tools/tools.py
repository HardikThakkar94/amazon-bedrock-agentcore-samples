"""
Visa MCP Tool Implementations
"""
import logging
import uuid
import urllib.parse
from mcp_instance import mcp
from visa.secure_token import get_secure_token_direct
from visa.helpers import get_secret
from visa.flow import (
    enroll_pan,
    provision_token,
    device_attestation_authenticate,
    device_attestation_register,
    device_binding,
    step_up,
    validate_otp,
    vic_enroll_card,
    vic_initiate_purchase_instructions,
    vic_get_payment_credentials,
)

logger = logging.getLogger(__name__)


@mcp.tool()
def visa_get_secure_token(clientAppId: str = "VICTestAccountTR") -> dict:
    """
    Get Visa OAuth secure token for authentication session.

    This token is required for card onboarding and device attestation flows.

    Args:
        clientAppId: Client application ID (default: "VICTestAccountTR")

    Returns:
        Dictionary containing secureToken and related authentication data
    """
    try:
        api_key = get_secret("visa/api-key", "us-east-1")
        result = get_secure_token_direct(api_key=api_key, client_app_id=clientAppId)

        if not result:
            return {
                "success": False,
                "error": "Failed to retrieve secure token"
            }

        return {
            "success": True,
            "secureToken": result["secureToken"],
            "requestID": result["requestID"],
            "proof_verifier": result.get("proof_verifier"),
            "device_fingerprint": result.get("device_fingerprint")
        }
    except Exception as e:
        logger.error(f"Error in visa_get_secure_token: {e}")
        return {
            "success": False,
            "error": str(e)
        }


@mcp.tool()
def visa_onboard_card(
    email: str,
    accountNumber: str,
    cvv2: str,
    expirationDate: str,
    clientAppId: str = "VICTestAccountTR",
    clientWalletAccountId: str = "40010062596"
) -> dict:
    """
    Onboard a card to Visa Token Service (enroll PAN + provision token).

    This combines enrollment and provisioning into a single operation.

    Args:
        email: User email address
        accountNumber: Card number (PAN)
        cvv2: Card CVV2 code
        expirationDate: Card expiration (format: "YYYY-MM")
        clientAppId: Client application ID (default: "VICTestAccountTR")
        clientWalletAccountId: Wallet account ID (default: "40010062596")

    Returns:
        Dictionary containing provisioned token ID and encrypted token info
    """
    try:
        # Generate session IDs
        x_request_id = str(uuid.uuid4())

        # Step 1: Enroll PAN
        pan_data = {
            "accountNumber": accountNumber,
            "cvv2": cvv2,
            "expirationDate": expirationDate
        }

        enroll_response = enroll_pan(
            email=email,
            pan_data=pan_data,
            client_app_id=clientAppId,
            client_wallet_account_id=clientWalletAccountId,
            x_request_id=x_request_id
        )

        vpan_enrollment_id = enroll_response.get("vPanEnrollmentID")
        if not vpan_enrollment_id:
            return {
                "success": False,
                "error": "Failed to get vPanEnrollmentID from enrollment response"
            }

        # Step 2: Provision token (pass browser_data=None for fallback)
        provision_response = provision_token(
            vpan_enrollment_id=vpan_enrollment_id,
            email=email,
            client_app_id=clientAppId,
            client_wallet_account_id=clientWalletAccountId,
            browser_data=None,
            x_request_id=x_request_id
        )

        token_info = provision_response.get("tokenInfo", {})

        return {
            "success": True,
            "vProvisionedTokenID": token_info.get("vProvisionedTokenID"),
            "encTokenInfo": token_info.get("encTokenInfo"),
            "x_request_id": x_request_id,
            "raw_response": provision_response
        }

    except Exception as e:
        logger.error(f"Error in visa_onboard_card: {e}")
        return {
            "success": False,
            "error": str(e)
        }


@mcp.tool()
def visa_device_attestation(
    email: str,
    secureToken: str,
    provisionedTokenId: str,
    clientAppId: str,
    x_request_id: str,
    step: str = "AUTHENTICATE",
    transactionAmount: str = "567.89"
) -> dict:
    """
    Perform device attestation (AUTHENTICATE or REGISTER step).

    AUTHENTICATE step: Verify device before transaction
    REGISTER step: Register device passkey/biometric

    Args:
        email: User email address
        secureToken: Secure token from visa_get_secure_token
        provisionedTokenId: Token ID from visa_onboard_card
        clientAppId: Client application ID
        x_request_id: Session request ID from onboarding
        step: "AUTHENTICATE" or "REGISTER" (default: "AUTHENTICATE")
        transactionAmount: Transaction amount (default: "567.89")

    Returns:
        Dictionary containing attestation options and identifier
    """
    try:
        client_reference_id = str(uuid.uuid4())

        # Minimal browser data (flow.py handles fallback)
        browser_data = {
            "userAgent": "Mozilla/5.0",
            "browserPlatform": "Web Platform",
            "ipAddress": "192.168.1.1"
        }

        if step == "AUTHENTICATE":
            response = device_attestation_authenticate(
                email=email,
                secure_token=secureToken,
                provisioned_token_id=provisionedTokenId,
                browser_data=browser_data,
                client_app_id=clientAppId,
                client_reference_id=client_reference_id,
                x_request_id=x_request_id,
                transaction_amount=transactionAmount
            )
        elif step == "REGISTER":
            response = device_attestation_register(
                provisioned_token_id=provisionedTokenId,
                email=email,
                secure_token=secureToken,
                browser_data=browser_data,
                client_app_id=clientAppId,
                client_reference_id=client_reference_id,
                x_request_id=x_request_id
            )
        else:
            return {
                "success": False,
                "error": f"Invalid step '{step}'. Must be 'AUTHENTICATE' or 'REGISTER'"
            }

        return {
            "success": True,
            "step": step,
            "identifier": response.get("identifier"),
            "client_reference_id": client_reference_id,
            "raw_response": response
        }

    except Exception as e:
        logger.error(f"Error in visa_device_attestation: {e}")
        return {
            "success": False,
            "error": str(e)
        }


@mcp.tool()
def visa_device_binding(
    secureToken: str,
    email: str,
    provisionedTokenId: str,
    clientAppId: str,
    x_request_id: str
) -> dict:
    """
    Bind device for FIDO/passkey authentication.

    This establishes device binding for future authentication flows.

    Args:
        secureToken: Secure token from visa_get_secure_token
        email: User email address
        provisionedTokenId: Token ID from visa_onboard_card
        clientAppId: Client application ID
        x_request_id: Session request ID from onboarding

    Returns:
        Dictionary containing device binding response
    """
    try:
        client_reference_id = str(uuid.uuid4())

        # Minimal browser data
        browser_data = {
            "userAgent": "Mozilla/5.0",
            "browserPlatform": "Web Platform",
            "ipAddress": "192.168.1.1"
        }

        response = device_binding(
            secure_token=secureToken,
            email=email,
            provisioned_token_id=provisionedTokenId,
            browser_data=browser_data,
            client_app_id=clientAppId,
            client_reference_id=client_reference_id,
            x_request_id=x_request_id
        )

        return {
            "success": True,
            "client_reference_id": client_reference_id,
            "raw_response": response
        }

    except Exception as e:
        logger.error(f"Error in visa_device_binding: {e}")
        return {
            "success": False,
            "error": str(e)
        }


@mcp.tool()
def visa_step_up(
    provisionedTokenId: str,
    identifier: str,
    clientAppId: str,
    x_request_id: str
) -> dict:
    """
    Select step-up authentication method (OTP).

    This initiates the step-up authentication flow for additional verification.

    Args:
        provisionedTokenId: Token ID from visa_onboard_card
        identifier: Identifier from device attestation response
        clientAppId: Client application ID
        x_request_id: Session request ID from onboarding

    Returns:
        Dictionary containing step-up options
    """
    try:
        client_reference_id = str(uuid.uuid4())

        response = step_up(
            provisioned_token_id=provisionedTokenId,
            identifier=identifier,
            client_app_id=clientAppId,
            client_reference_id=client_reference_id,
            x_request_id=x_request_id
        )

        return {
            "success": True,
            "client_reference_id": client_reference_id,
            "raw_response": response
        }

    except Exception as e:
        logger.error(f"Error in visa_step_up: {e}")
        return {
            "success": False,
            "error": str(e)
        }


@mcp.tool()
def visa_validate_otp(
    provisionedTokenId: str,
    otpValue: str,
    clientAppId: str,
    x_request_id: str
) -> dict:
    """
    Validate OTP for step-up authentication.

    This validates the OTP sent to the user's registered contact method.

    Args:
        provisionedTokenId: Token ID from visa_onboard_card
        otpValue: OTP code received by user
        clientAppId: Client application ID
        x_request_id: Session request ID from onboarding

    Returns:
        Dictionary containing validation result
    """
    try:
        client_reference_id = str(uuid.uuid4())

        response = validate_otp(
            provisioned_token_id=provisionedTokenId,
            otp_value=otpValue,
            client_app_id=clientAppId,
            client_reference_id=client_reference_id,
            x_request_id=x_request_id
        )

        return {
            "success": True,
            "client_reference_id": client_reference_id,
            "raw_response": response
        }

    except Exception as e:
        logger.error(f"Error in visa_validate_otp: {e}")
        return {
            "success": False,
            "error": str(e)
        }


@mcp.tool()
def visa_complete_passkey(fidoBlob: str) -> dict:
    """
    Parse FIDO passkey authentication response.

    Extracts code and hint from URL-encoded fidoBlob returned by Visa iframe.

    Args:
        fidoBlob: URL-encoded FIDO blob from Visa passkey flow

    Returns:
        Dictionary containing extracted code and hint
    """
    try:
        # Parse URL-encoded fidoBlob
        parsed = urllib.parse.parse_qs(fidoBlob)

        code = parsed.get("code", [None])[0]
        hint = parsed.get("hint", [None])[0]

        if not code:
            return {
                "success": False,
                "error": "No 'code' found in fidoBlob"
            }

        return {
            "success": True,
            "code": code,
            "hint": hint,
            "raw_parsed": parsed
        }

    except Exception as e:
        logger.error(f"Error in visa_complete_passkey: {e}")
        return {
            "success": False,
            "error": str(e)
        }


@mcp.tool()
def visa_vic_enroll_card(
    email: str,
    provisionedTokenId: str,
    clientAppId: str
) -> dict:
    """
    Enroll provisioned token with Visa In-Commerce (VIC) for AI agent payments.

    This registers the card token with VIC for autonomous payment instructions.

    Args:
        email: User email address
        provisionedTokenId: Token ID from visa_onboard_card
        clientAppId: Client application ID

    Returns:
        Dictionary containing VIC enrollment status and client reference ID
    """
    try:
        # Generate session IDs for VIC enrollment
        client_reference_id = str(uuid.uuid4())
        client_device_id = str(uuid.uuid4())
        consumer_id = str(uuid.uuid4())

        response = vic_enroll_card(
            email=email,
            provisioned_token_id=provisionedTokenId,
            client_app_id=clientAppId,
            client_reference_id=client_reference_id,
            client_device_id=client_device_id,
            consumer_id=consumer_id
        )

        return {
            "success": True,
            "clientReferenceId": response.get("clientReferenceId"),
            "status": response.get("status"),
            "client_device_id": client_device_id,
            "consumer_id": consumer_id,
            "raw_response": response
        }

    except Exception as e:
        logger.error(f"Error in visa_vic_enroll_card: {e}")
        return {
            "success": False,
            "error": str(e)
        }


@mcp.tool()
def visa_vic_initiate_purchase(
    provisionedTokenId: str,
    consumerId: str,
    clientAppId: str,
    consumerRequest: str,
    clientReferenceId: str,
    clientDeviceId: str,
    authIdentifier: str,
    dfpSessionId: str,
    iframeAuthFidoBlob: str,
    transactionAmount: str = "444.44"
) -> dict:
    """
    Initiate VIC purchase instructions with passkey assurance data.

    This creates a payment mandate for AI agent to execute purchases.

    Args:
        provisionedTokenId: Token ID from visa_onboard_card
        consumerId: Consumer ID from visa_vic_enroll_card
        clientAppId: Client application ID
        consumerRequest: Purchase intent description (max 150 chars)
        clientReferenceId: Client reference ID from enrollment
        clientDeviceId: Client device ID from enrollment
        authIdentifier: Identifier from device attestation
        dfpSessionId: DFP session ID from iframe
        iframeAuthFidoBlob: FIDO assertion code from passkey auth
        transactionAmount: Max transaction amount (default: "444.44")

    Returns:
        Dictionary containing instructionId for payment credentials
    """
    try:
        # Generate mandate ID
        mandate_id = str(uuid.uuid4())

        # Truncate consumer request to 150 chars
        truncated_request = consumerRequest[:150]

        response = vic_initiate_purchase_instructions(
            provisioned_token_id=provisionedTokenId,
            consumer_id=consumerId,
            client_app_id=clientAppId,
            mandate_id=mandate_id,
            consumer_request=truncated_request,
            client_reference_id=clientReferenceId,
            client_device_id=clientDeviceId,
            auth_identifier=authIdentifier,
            dfp_session_id=dfpSessionId,
            iframe_auth_fido_blob=iframeAuthFidoBlob,
            transaction_amount=transactionAmount
        )

        return {
            "success": True,
            "instructionId": response.get("instructionId"),
            "clientReferenceId": response.get("clientReferenceId"),
            "status": response.get("status"),
            "mandate_id": mandate_id,
            "raw_response": response
        }

    except Exception as e:
        logger.error(f"Error in visa_vic_initiate_purchase: {e}")
        return {
            "success": False,
            "error": str(e)
        }


@mcp.tool()
def visa_vic_payment_credentials(
    instructionId: str,
    provisionedTokenId: str,
    clientAppId: str,
    clientReferenceId: str,
    merchantUrl: str,
    merchantName: str,
    transactionAmount: str
) -> dict:
    """
    Get payment credentials (cryptogram) for authorization.

    This retrieves the cryptogram needed to complete the payment transaction.

    Args:
        instructionId: Instruction ID from visa_vic_initiate_purchase
        provisionedTokenId: Token ID from visa_onboard_card
        clientAppId: Client application ID
        clientReferenceId: Client reference ID from enrollment
        merchantUrl: Merchant website URL
        merchantName: Merchant name
        transactionAmount: Transaction amount

    Returns:
        Dictionary containing signedPayload with cryptogram
    """
    try:
        response = vic_get_payment_credentials(
            instruction_id=instructionId,
            provisioned_token_id=provisionedTokenId,
            client_app_id=clientAppId,
            client_reference_id=clientReferenceId,
            merchant_url=merchantUrl,
            merchant_name=merchantName,
            transaction_amount=transactionAmount
        )

        return {
            "success": True,
            "signedPayload": response.get("signedPayload"),
            "instructionId": response.get("instructionId"),
            "status": response.get("status"),
            "raw_response": response
        }

    except Exception as e:
        logger.error(f"Error in visa_vic_payment_credentials: {e}")
        return {
            "success": False,
            "error": str(e)
        }
