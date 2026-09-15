import os
import json
import httpx
from mcp.server import MCPServer

mcp = MCPServer("Tenable Security MCP")


def nessus_request(method: str, endpoint: str, **kwargs):
    nessus_url = os.getenv("NESSUS_URL", "https://localhost:8834")
    access_key = os.getenv("NESSUS_ACCESS_KEY")
    secret_key = os.getenv("NESSUS_SECRET_KEY")

    if not access_key or not secret_key:
        return {"error": "Nessus API credentials are not configured."}

    headers = {
        "X-ApiKeys": f"accessKey={access_key};secretKey={secret_key}",
        "Accept": "application/json",
        "Content-Type": "application/json",
    }

    response = httpx.request(
        method,
        f"{nessus_url}{endpoint}",
        headers=headers,
        verify=False,
        timeout=60,
        **kwargs,
    )

    response.raise_for_status()

    if not response.content:
        return {"status": "success"}

    return response.json()


@mcp.tool()
def get_nessus_server_info() -> str:
    """Get basic information about the Nessus server."""
    result = nessus_request("GET", "/server/properties")
    return json.dumps(result, indent=2)


if __name__ == "__main__":
    mcp.run()
