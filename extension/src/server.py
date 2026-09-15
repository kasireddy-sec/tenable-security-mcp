import os
import json
import httpx

from mcp.server import MCPServer


mcp = MCPServer("Tenable Security MCP")


def nessus_request(method: str, endpoint: str, **kwargs):
    """Common helper for Nessus REST API requests."""

    nessus_url = os.getenv(
        "NESSUS_URL",
        "https://localhost:8834"
    ).rstrip("/")

    access_key = os.getenv("NESSUS_ACCESS_KEY")
    secret_key = os.getenv("NESSUS_SECRET_KEY")

    if not access_key or not secret_key:
        return {
            "error": "Nessus API credentials are not configured."
        }

    headers = {
        "X-ApiKeys": (
            f"accessKey={access_key};"
            f"secretKey={secret_key}"
        ),
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

    try:
        return response.json()
    except Exception:
        return {"response": response.text}


@mcp.tool()
def get_nessus_server_info() -> str:
    """Get basic information about the Nessus server."""
    result = nessus_request(
        "GET",
        "/server/properties"
    )
    return json.dumps(result, indent=2)


@mcp.tool()
def list_nessus_scans() -> str:
    """List all scans configured in Nessus."""
    result = nessus_request(
        "GET",
        "/scans"
    )
    return json.dumps(result, indent=2)


@mcp.tool()
def get_nessus_scan_details(scan_id: int) -> str:
    """Get details and latest results for a Nessus scan."""
    result = nessus_request(
        "GET",
        f"/scans/{scan_id}"
    )
    return json.dumps(result, indent=2)


@mcp.tool()
def get_nessus_scan_status(scan_id: int) -> str:
    """Get the current status of a Nessus scan."""

    result = nessus_request(
        "GET",
        f"/scans/{scan_id}"
    )

    if "error" in result:
        return json.dumps(result, indent=2)

    info = result.get("info", {})

    status = {
        "scan_id": scan_id,
        "name": info.get("name"),
        "status": info.get("status"),
        "progress": info.get("progress"),
        "folder_id": info.get("folder_id"),
        "last_modification_date": info.get(
            "last_modification_date"
        ),
    }

    return json.dumps(status, indent=2)


@mcp.tool()
def get_nessus_host_details(
    scan_id: int,
    host_id: int
) -> str:
    """Get vulnerability information for a host in a scan."""

    result = nessus_request(
        "GET",
        f"/scans/{scan_id}/hosts/{host_id}"
    )

    return json.dumps(result, indent=2)


@mcp.tool()
def get_nessus_vulnerability_details(
    scan_id: int,
    host_id: int,
    plugin_id: int
) -> str:
    """Get detailed information and plugin output for a vulnerability."""

    result = nessus_request(
        "GET",
        f"/scans/{scan_id}/hosts/{host_id}/plugins/{plugin_id}"
    )

    return json.dumps(result, indent=2)


@mcp.tool()
def list_nessus_policies() -> str:
    """List available Nessus scan policies."""

    result = nessus_request(
        "GET",
        "/policies"
    )

    return json.dumps(result, indent=2)


@mcp.tool()
def list_nessus_folders() -> str:
    """List Nessus scan folders."""

    result = nessus_request(
        "GET",
        "/folders"
    )

    return json.dumps(result, indent=2)


@mcp.tool()
def list_nessus_agents() -> str:
    """List Nessus agents."""

    result = nessus_request(
        "GET",
        "/agents"
    )

    return json.dumps(result, indent=2)


@mcp.tool()
def get_nessus_scan_history(
    scan_id: int
) -> str:
    """Get historical runs of a Nessus scan."""

    result = nessus_request(
        "GET",
        f"/scans/{scan_id}/history"
    )

    return json.dumps(result, indent=2)


@mcp.tool()
def get_nessus_scan_history_details(
    scan_id: int,
    history_id: int
) -> str:
    """Get details for a specific historical scan result."""

    result = nessus_request(
        "GET",
        f"/scans/{scan_id}/history/{history_id}"
    )

    return json.dumps(result, indent=2)


@mcp.tool()
def launch_nessus_scan(
    scan_id: int
) -> str:
    """Launch a Nessus scan using its configured targets."""

    result = nessus_request(
        "POST",
        f"/scans/{scan_id}/launch"
    )

    return json.dumps(result, indent=2)


@mcp.tool()
def stop_nessus_scan(
    scan_id: int
) -> str:
    """Stop a running Nessus scan."""

    result = nessus_request(
        "POST",
        f"/scans/{scan_id}/stop"
    )

    return json.dumps(result, indent=2)


@mcp.tool()
def get_nessus_plugin(
    plugin_id: int
) -> str:
    """Get information about a Nessus plugin."""

    result = nessus_request(
        "GET",
        f"/plugins/plugin/{plugin_id}"
    )

    return json.dumps(result, indent=2)


@mcp.tool()
def list_nessus_users() -> str:
    """List users configured in Nessus."""

    result = nessus_request(
        "GET",
        "/users"
    )

    return json.dumps(result, indent=2)


if __name__ == "__main__":
    mcp.run()

