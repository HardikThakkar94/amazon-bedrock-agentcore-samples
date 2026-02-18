"""
Visa Tools MCP Server

Exposes Visa payment APIs as MCP tools for AI agents.
Preserves all existing Visa API integration logic.
"""
import os
import logging
import boto3
from mcp.server import FastMCP

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Environment configuration
REGION = os.getenv("AWS_REGION")
if not REGION:
    raise ValueError("AWS_REGION environment variable is required")

# Initialize AWS clients
secrets_client = boto3.client("secretsmanager", region_name=REGION)

# Create MCP server
mcp = FastMCP("Visa Tools", host="0.0.0.0", stateless_http=True)

# Verify secrets are accessible
def ensure_secrets_accessible():
    """Verify secrets are accessible"""
    try:
        secrets_client.get_secret_value(SecretId="visa/api-key")
        logger.info("✓ Visa secrets accessible")
    except Exception as e:
        logger.warning(f"⚠️  Could not verify Visa secrets: {e}")

ensure_secrets_accessible()

# Import all tools (must be after mcp is defined)
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
    visa_vic_payment_credentials
)

# Health check endpoint
@mcp.get("/health")
def health_check():
    """Health check endpoint for container orchestration"""
    return {
        "status": "healthy",
        "service": "visa-mcp",
        "tools": 10
    }

if __name__ == "__main__":
    logger.info("Starting Visa Tools MCP Server...")
    logger.info("10 Visa tools registered")
    mcp.run(transport="streamable-http")
