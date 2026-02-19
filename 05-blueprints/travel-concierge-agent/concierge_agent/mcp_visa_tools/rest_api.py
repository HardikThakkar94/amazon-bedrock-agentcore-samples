"""
REST API routes for Visa MCP Tools

Registers FastAPI routes that wrap MCP tools for frontend HTTP access.
"""
import logging
from fastapi import Request
from fastapi.responses import JSONResponse

# Import MCP tool implementations
from tools import (
    visa_get_secure_token,
    visa_onboard_card,
    visa_device_attestation,
    visa_device_binding,
    visa_step_up,
    visa_validate_otp,
    visa_complete_passkey,
    visa_vic_enroll_card,
    visa_vic_initiate_purchase,
    visa_vic_payment_credentials,
)

logger = logging.getLogger(__name__)


def register_rest_routes(app):
    """Register REST API routes on the FastAPI app."""

    @app.get("/")
    async def health_check():
        """Health check endpoint."""
        return {
            "status": "healthy",
            "service": "Visa MCP REST API",
            "version": "1.0"
        }

    @app.get("/api/visa/secure-token")
    async def secure_token(clientAppId: str = "VICTestAccountTR"):
        """Get Visa OAuth secure token."""
        try:
            result = visa_get_secure_token(clientAppId=clientAppId)
            return JSONResponse(content=result)
        except Exception as e:
            logger.error(f"Error in /api/visa/secure-token: {e}")
            return JSONResponse(
                content={"success": False, "error": str(e)},
                status_code=500
            )

    @app.post("/api/visa/onboard-card")
    async def onboard_card(request: Request):
        """Onboard a card (enroll PAN + provision token)."""
        try:
            data = await request.json()
            result = visa_onboard_card(
                email=data["email"],
                accountNumber=data["cardNumber"],
                cvv2=data["cvv"],
                expirationDate=data["expirationDate"],
                clientAppId=data.get("clientAppId", "VICTestAccountTR"),
                clientWalletAccountId=data.get("clientWalletAccountId", "40010062596")
            )
            return JSONResponse(content=result)
        except Exception as e:
            logger.error(f"Error in /api/visa/onboard-card: {e}")
            return JSONResponse(
                content={"success": False, "error": str(e)},
                status_code=500
            )

    @app.post("/api/visa/device-attestation")
    async def device_attestation(request: Request):
        """Perform device attestation (AUTHENTICATE or REGISTER)."""
        try:
            data = await request.json()
            result = visa_device_attestation(
                email=data["email"],
                secureToken=data["secureToken"],
                provisionedTokenId=data["provisionedTokenId"],
                clientAppId=data["clientAppId"],
                x_request_id=data["xRequestId"],
                step=data.get("step", "AUTHENTICATE"),
                transactionAmount=data.get("transactionAmount", "567.89")
            )
            return JSONResponse(content=result)
        except Exception as e:
            logger.error(f"Error in /api/visa/device-attestation: {e}")
            return JSONResponse(
                content={"success": False, "error": str(e)},
                status_code=500
            )

    @app.post("/api/visa/complete-passkey")
    async def complete_passkey(request: Request):
        """Parse FIDO passkey authentication response."""
        try:
            data = await request.json()
            result = visa_complete_passkey(fidoBlob=data["fidoBlob"])
            return JSONResponse(content=result)
        except Exception as e:
            logger.error(f"Error in /api/visa/complete-passkey: {e}")
            return JSONResponse(
                content={"success": False, "error": str(e)},
                status_code=500
            )

    @app.post("/api/visa/device-binding")
    async def device_binding(request: Request):
        """Bind device for FIDO/passkey authentication."""
        try:
            data = await request.json()
            result = visa_device_binding(
                secureToken=data["secureToken"],
                email=data["email"],
                provisionedTokenId=data["provisionedTokenId"],
                clientAppId=data["clientAppId"],
                x_request_id=data["xRequestId"]
            )
            return JSONResponse(content=result)
        except Exception as e:
            logger.error(f"Error in /api/visa/device-binding: {e}")
            return JSONResponse(
                content={"success": False, "error": str(e)},
                status_code=500
            )

    @app.post("/api/visa/step-up")
    async def step_up(request: Request):
        """Select step-up authentication method (OTP)."""
        try:
            data = await request.json()
            result = visa_step_up(
                provisionedTokenId=data["provisionedTokenId"],
                identifier=data["identifier"],
                clientAppId=data["clientAppId"],
                x_request_id=data["xRequestId"]
            )
            return JSONResponse(content=result)
        except Exception as e:
            logger.error(f"Error in /api/visa/step-up: {e}")
            return JSONResponse(
                content={"success": False, "error": str(e)},
                status_code=500
            )

    @app.post("/api/visa/validate-otp")
    async def validate_otp(request: Request):
        """Validate OTP for step-up authentication."""
        try:
            data = await request.json()
            result = visa_validate_otp(
                provisionedTokenId=data["provisionedTokenId"],
                otpValue=data["otpValue"],
                clientAppId=data["clientAppId"],
                x_request_id=data["xRequestId"]
            )
            return JSONResponse(content=result)
        except Exception as e:
            logger.error(f"Error in /api/visa/validate-otp: {e}")
            return JSONResponse(
                content={"success": False, "error": str(e)},
                status_code=500
            )

    @app.post("/api/visa/vic/enroll-card")
    async def vic_enroll_card(request: Request):
        """Enroll provisioned token with Visa In-Commerce (VIC)."""
        try:
            data = await request.json()
            result = visa_vic_enroll_card(
                email=data["email"],
                provisionedTokenId=data["provisionedTokenId"],
                clientAppId=data["clientAppId"]
            )
            return JSONResponse(content=result)
        except Exception as e:
            logger.error(f"Error in /api/visa/vic/enroll-card: {e}")
            return JSONResponse(
                content={"success": False, "error": str(e)},
                status_code=500
            )

    @app.post("/api/visa/vic/initiate-purchase")
    async def vic_initiate_purchase(request: Request):
        """Initiate VIC purchase instructions."""
        try:
            data = await request.json()
            result = visa_vic_initiate_purchase(
                provisionedTokenId=data["provisionedTokenId"],
                consumerId=data["consumerId"],
                clientAppId=data["clientAppId"],
                consumerRequest=data["consumerRequest"],
                clientReferenceId=data["clientReferenceId"],
                clientDeviceId=data["clientDeviceId"],
                authIdentifier=data["authIdentifier"],
                dfpSessionId=data["dfpSessionId"],
                iframeAuthFidoBlob=data["iframeAuthFidoBlob"],
                transactionAmount=data.get("transactionAmount", "444.44")
            )
            return JSONResponse(content=result)
        except Exception as e:
            logger.error(f"Error in /api/visa/vic/initiate-purchase: {e}")
            return JSONResponse(
                content={"success": False, "error": str(e)},
                status_code=500
            )

    @app.post("/api/visa/vic/payment-credentials")
    async def vic_payment_credentials(request: Request):
        """Get payment credentials (cryptogram) for authorization."""
        try:
            data = await request.json()
            result = visa_vic_payment_credentials(
                instructionId=data["instructionId"],
                provisionedTokenId=data["provisionedTokenId"],
                clientAppId=data["clientAppId"],
                clientReferenceId=data["clientReferenceId"],
                merchantUrl=data["merchantUrl"],
                merchantName=data["merchantName"],
                transactionAmount=data["transactionAmount"]
            )
            return JSONResponse(content=result)
        except Exception as e:
            logger.error(f"Error in /api/visa/vic/payment-credentials: {e}")
            return JSONResponse(
                content={"success": False, "error": str(e)},
                status_code=500
            )
