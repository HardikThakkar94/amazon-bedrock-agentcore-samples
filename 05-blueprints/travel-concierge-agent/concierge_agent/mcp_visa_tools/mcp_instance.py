"""
MCP Server Instance

Shared MCP instance to avoid circular imports.
"""
from mcp.server import FastMCP

# Create MCP server instance
mcp = FastMCP("Visa Tools", host="0.0.0.0", stateless_http=True)
