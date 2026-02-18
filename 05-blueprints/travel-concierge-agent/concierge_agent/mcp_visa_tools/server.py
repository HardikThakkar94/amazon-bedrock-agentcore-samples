"""
Visa Tools MCP Server

Exposes Visa payment APIs as MCP tools for AI agents.
Preserves all existing Visa API integration logic.
"""
import os
import logging
import boto3
from mcp_instance import mcp

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Environment configuration
REGION = os.getenv("AWS_REGION")
if not REGION:
    raise ValueError("AWS_REGION environment variable is required")

# Initialize AWS clients
secrets_client = boto3.client("secretsmanager", region_name=REGION)

# Verify secrets are accessible
def ensure_secrets_accessible():
    """Verify secrets are accessible"""
    try:
        secrets_client.get_secret_value(SecretId="visa/api-key")
        logger.info("✓ Visa secrets accessible")
    except Exception as e:
        logger.warning(f"⚠️  Could not verify Visa secrets: {e}")

ensure_secrets_accessible()

# Import tools module to register all @mcp.tool() decorators
import tools  # noqa: F401

if __name__ == "__main__":
    logger.info("Starting Visa Tools MCP Server...")
    logger.info("10 Visa tools registered")
    mcp.run(transport="streamable-http")
