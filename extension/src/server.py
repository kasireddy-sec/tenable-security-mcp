import os
import json
import re
from datetime import datetime, timezone, timedelta

import httpx

from mcp.server import MCPServer


mcp = MCPServer("Tenable Security MCP")


# ============================================================
# CONFIGURATION
# ============================================================

DEFAULT_NESSUS_URL = "https://localhost:8834"
DEFAULT_TENABLE_CLOUD_URL = "https://cloud.tenable.com"

NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
CISA_KEV_URL = (
    "https://www.cisa.gov/sites/default/files/feeds/"
    "known_exploited_vulnerabilities.json"
)
EPSS_API_URL = "https://api.first.org/data/v1/epss"
GITHUB_API_URL = "https://api.github.com/search/repositories"


# ============================================================
# GENERAL HELPERS
# ============================================================

def json_result(data) -> str:
    """Return consistently formatted JSON to Claude."""

    return json.dumps(
        data,
        indent=2,
        default=str
    )


def safe_int(value, default=0):
    """Safely convert a value to an integer."""

    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def safe_float(value, default=0.0):
    """Safely convert a value to a float."""

    try:
        return float(value)
    except (TypeError, ValueError):
        return default


def validate_cve(cve_id: str) -> str:
    """Validate and normalize a CVE identifier."""

    normalized = cve_id.strip().upper()

    if not re.fullmatch(
        r"CVE-\d{4}-\d{4,}",
        normalized
    ):
        raise ValueError(
            "Invalid CVE format. Example: CVE-2024-3094"
        )

    return normalized


def extract_cves(value) -> list[str]:
    """Extract unique CVE identifiers from arbitrary text."""

    if not value:
        return []

    text = str(value).upper()

    matches = re.findall(
        r"CVE-\d{4}-\d{4,}",
        text
    )

    return sorted(set(matches))


def extract_cves_from_object(value) -> list[str]:
    """Recursively extract CVEs from dictionaries/lists."""

    found = set()

    if isinstance(value, dict):
        for key, item in value.items():

            if str(key).lower() in {
                "cve",
                "cves",
                "cve_id",
                "cve_ids"
            }:
                if isinstance(item, list):
                    for entry in item:
                        found.update(
                            extract_cves(str(entry))
                        )
                else:
                    found.update(
                        extract_cves(str(item))
                    )

            found.update(
                extract_cves_from_object(item)
            )

    elif isinstance(value, list):

        for item in value:
            found.update(
                extract_cves_from_object(item)
            )

    elif isinstance(value, str):

        found.update(
            extract_cves(value)
        )

    return sorted(found)


# ============================================================
# NESSUS API HELPER
# ============================================================

def nessus_request(
    method: str,
    endpoint: str,
    **kwargs
):
    """Common helper for Nessus REST API requests."""

    nessus_url = os.getenv(
        "NESSUS_URL",
        DEFAULT_NESSUS_URL
    ).rstrip("/")

    access_key = os.getenv(
        "NESSUS_ACCESS_KEY"
    )

    secret_key = os.getenv(
        "NESSUS_SECRET_KEY"
    )

    if not access_key or not secret_key:
        return {
            "error": (
                "Nessus API credentials are not configured."
            )
        }

    headers = {
        "X-ApiKeys": (
            f"accessKey={access_key};"
            f"secretKey={secret_key}"
        ),
        "Accept": "application/json",
        "Content-Type": "application/json",
    }

    try:

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
            return {
                "status": "success"
            }

        try:
            return response.json()

        except Exception:
            return {
                "response": response.text
            }

    except httpx.HTTPStatusError as exc:

        return {
            "error": (
                f"Nessus API returned HTTP "
                f"{exc.response.status_code}"
            )
        }

    except httpx.TimeoutException:

        return {
            "error": "Nessus API request timed out."
        }

    except httpx.RequestError as exc:

        return {
            "error": (
                f"Unable to connect to Nessus: {exc}"
            )
        }


# ============================================================
# TENABLE VULNERABILITY MANAGEMENT API HELPER
# ============================================================

def tenable_cloud_request(
    method: str,
    endpoint: str,
    **kwargs
):
    """
    Common helper for Tenable Vulnerability Management /
    Tenable cloud APIs.

    Credentials are intentionally separate from Nessus.
    """

    base_url = os.getenv(
        "TENABLE_CLOUD_URL",
        DEFAULT_TENABLE_CLOUD_URL
    ).rstrip("/")

    access_key = os.getenv(
        "TENABLE_CLOUD_ACCESS_KEY"
    )

    secret_key = os.getenv(
        "TENABLE_CLOUD_SECRET_KEY"
    )

    if not access_key or not secret_key:

        return {
            "error": (
                "Tenable Cloud API credentials are not "
                "configured. Set TENABLE_CLOUD_ACCESS_KEY "
                "and TENABLE_CLOUD_SECRET_KEY."
            )
        }

    headers = {
        "X-ApiKeys": (
            f"accessKey={access_key};"
            f"secretKey={secret_key}"
        ),
        "Accept": "application/json",
        "Content-Type": "application/json",
    }

    try:

        response = httpx.request(
            method,
            f"{base_url}{endpoint}",
            headers=headers,
            timeout=60,
            **kwargs,
        )

        response.raise_for_status()

        if not response.content:
            return {
                "status": "success"
            }

        try:
            return response.json()

        except Exception:
            return {
                "response": response.text
            }

    except httpx.HTTPStatusError as exc:

        return {
            "error": (
                f"Tenable Cloud API returned HTTP "
                f"{exc.response.status_code}"
            )
        }

    except httpx.TimeoutException:

        return {
            "error": "Tenable Cloud API request timed out."
        }

    except httpx.RequestError as exc:

        return {
            "error": (
                f"Unable to connect to Tenable Cloud: {exc}"
            )
        }


# ============================================================
# NVD API HELPER
# ============================================================

def nvd_request(cve_id: str) -> dict:
    """Retrieve CVE information from NVD."""

    try:
        cve_id = validate_cve(cve_id)

    except ValueError as exc:

        return {
            "error": str(exc)
        }

    try:

        response = httpx.get(
            NVD_API_URL,
            params={
                "cveId": cve_id
            },
            headers={
                "Accept": "application/json"
            },
            timeout=30,
        )

        response.raise_for_status()

        return response.json()

    except httpx.HTTPStatusError as exc:

        return {
            "error": (
                f"NVD API returned HTTP "
                f"{exc.response.status_code}"
            )
        }

    except httpx.TimeoutException:

        return {
            "error": "NVD API request timed out."
        }

    except httpx.RequestError as exc:

        return {
            "error": (
                f"Unable to connect to NVD: {exc}"
            )
        }

    except ValueError:

        return {
            "error": (
                "NVD returned an invalid JSON response."
            )
        }


# ============================================================
# CISA KEV API HELPER
# ============================================================

def get_kev_catalog() -> dict:
    """Download the current CISA Known Exploited Vulnerabilities catalog."""

    try:

        response = httpx.get(
            CISA_KEV_URL,
            headers={
                "Accept": "application/json"
            },
            timeout=30,
        )

        response.raise_for_status()

        return response.json()

    except httpx.HTTPStatusError as exc:

        return {
            "error": (
                f"CISA KEV API returned HTTP "
                f"{exc.response.status_code}"
            )
        }

    except httpx.TimeoutException:

        return {
            "error": "CISA KEV request timed out."
        }

    except httpx.RequestError as exc:

        return {
            "error": (
                f"Unable to connect to CISA KEV: {exc}"
            )
        }

    except ValueError:

        return {
            "error": (
                "CISA KEV returned invalid JSON."
            )
        }


# ============================================================
# EPSS API HELPER
# ============================================================

def epss_request(cve_id: str) -> dict:
    """Retrieve EPSS score for a CVE."""

    try:
        cve_id = validate_cve(cve_id)

    except ValueError as exc:

        return {
            "error": str(exc)
        }

    try:

        response = httpx.get(
            EPSS_API_URL,
            params={
                "cve": cve_id
            },
            headers={
                "Accept": "application/json"
            },
            timeout=30,
        )

        response.raise_for_status()

        return response.json()

    except httpx.HTTPStatusError as exc:

        return {
            "error": (
                f"EPSS API returned HTTP "
                f"{exc.response.status_code}"
            )
        }

    except httpx.TimeoutException:

        return {
            "error": "EPSS API request timed out."
        }

    except httpx.RequestError as exc:

        return {
            "error": (
                f"Unable to connect to EPSS: {exc}"
            )
        }

    except ValueError:

        return {
            "error": (
                "EPSS returned invalid JSON."
            )
        }


# ============================================================
# EXISTING NESSUS TOOLS
# ============================================================

@mcp.tool()
def get_nessus_server_info() -> str:
    """Get basic information about the Nessus server."""

    result = nessus_request(
        "GET",
        "/server/properties"
    )

    return json_result(result)


@mcp.tool()
def list_nessus_scans() -> str:
    """List all scans configured in Nessus."""

    result = nessus_request(
        "GET",
        "/scans"
    )

    return json_result(result)


@mcp.tool()
def get_nessus_scan_details(
    scan_id: int
) -> str:
    """Get details and latest results for a Nessus scan."""

    result = nessus_request(
        "GET",
        f"/scans/{scan_id}"
    )

    return json_result(result)


@mcp.tool()
def get_nessus_scan_status(
    scan_id: int
) -> str:
    """Get the current status of a Nessus scan."""

    result = nessus_request(
        "GET",
        f"/scans/{scan_id}"
    )

    if "error" in result:
        return json_result(result)

    info = result.get(
        "info",
        {}
    )

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

    return json_result(status)


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

    return json_result(result)


@mcp.tool()
def get_nessus_vulnerability_details(
    scan_id: int,
    host_id: int,
    plugin_id: int
) -> str:
    """Get detailed information and plugin output for a vulnerability."""

    result = nessus_request(
        "GET",
        f"/scans/{scan_id}/hosts/"
        f"{host_id}/plugins/{plugin_id}"
    )

    return json_result(result)


@mcp.tool()
def list_nessus_policies() -> str:
    """List available Nessus scan policies."""

    result = nessus_request(
        "GET",
        "/policies"
    )

    return json_result(result)


@mcp.tool()
def list_nessus_folders() -> str:
    """List Nessus scan folders."""

    result = nessus_request(
        "GET",
        "/folders"
    )

    return json_result(result)


@mcp.tool()
def list_nessus_agents() -> str:
    """List Nessus agents."""

    result = nessus_request(
        "GET",
        "/agents"
    )

    return json_result(result)


@mcp.tool()
def get_nessus_scan_history(
    scan_id: int
) -> str:
    """Get historical runs of a Nessus scan."""

    result = nessus_request(
        "GET",
        f"/scans/{scan_id}/history"
    )

    return json_result(result)


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

    return json_result(result)


@mcp.tool()
def launch_nessus_scan(
    scan_id: int
) -> str:
    """Launch a Nessus scan using its configured targets."""

    result = nessus_request(
        "POST",
        f"/scans/{scan_id}/launch"
    )

    return json_result(result)


@mcp.tool()
def stop_nessus_scan(
    scan_id: int
) -> str:
    """Stop a running Nessus scan."""

    result = nessus_request(
        "POST",
        f"/scans/{scan_id}/stop"
    )

    return json_result(result)


@mcp.tool()
def get_nessus_plugin(
    plugin_id: int
) -> str:
    """Get information about a Nessus plugin."""

    result = nessus_request(
        "GET",
        f"/plugins/plugin/{plugin_id}"
    )

    return json_result(result)


@mcp.tool()
def list_nessus_users() -> str:
    """List users configured in Nessus."""

    result = nessus_request(
        "GET",
        "/users"
    )

    return json_result(result)


# ============================================================
# ASSET SCAN AGE
# ============================================================

@mcp.tool()
def find_assets_not_scanned_since(
    days: int = 7
) -> str:
    """
    Find Nessus hosts whose latest known scan result is older
    than the specified number of days.

    Example:
    find_assets_not_scanned_since(7)
    """

    if days < 0:
        return json_result({
            "error": "days must be zero or greater."
        })

    scans_result = nessus_request(
        "GET",
        "/scans"
    )

    if "error" in scans_result:
        return json_result(scans_result)

    scan_list = scans_result.get(
        "scans",
        []
    )

    cutoff = datetime.now(
        timezone.utc
    ) - timedelta(
        days=days
    )

    assets = {}

    for scan in scan_list:

        scan_id = scan.get("id")

        if not scan_id:
            continue

        details = nessus_request(
            "GET",
            f"/scans/{scan_id}"
        )

        if "error" in details:
            continue

        hosts = details.get(
            "hosts",
            []
        )

        for host in hosts:

            host_id = host.get("host_id")

            host_name = (
                host.get("hostname")
                or host.get("host-ip")
                or host.get("host")
                or host.get("name")
                or str(host_id)
            )

            timestamp = (
                host.get("last_scanned")
                or host.get("last_scanned_date")
                or host.get("scan_start")
                or host.get("last_scan")
            )

            if not timestamp:
                continue

            try:

                if isinstance(
                    timestamp,
                    (int, float)
                ):

                    scan_time = datetime.fromtimestamp(
                        timestamp,
                        tz=timezone.utc
                    )

                else:

                    scan_time = datetime.fromisoformat(
                        str(timestamp).replace(
                            "Z",
                            "+00:00"
                        )
                    )

                    if scan_time.tzinfo is None:
                        scan_time = scan_time.replace(
                            tzinfo=timezone.utc
                        )

            except Exception:
                continue

            current = assets.get(
                host_name
            )

            if (
                current is None
                or scan_time > current["last_scanned_datetime"]
            ):

                assets[host_name] = {
                    "host": host_name,
                    "host_id": host_id,
                    "last_scanned_datetime": scan_time,
                    "last_scanned": scan_time.isoformat(),
                    "scan_id": scan_id,
                    "scan_name": scan.get("name"),
                }

    not_scanned = []

    for asset in assets.values():

        if asset["last_scanned_datetime"] < cutoff:

            asset_copy = dict(asset)

            asset_copy.pop(
                "last_scanned_datetime",
                None
            )

            asset_copy["days_since_scan"] = (
                datetime.now(
                    timezone.utc
                ) - asset["last_scanned_datetime"]
            ).days

            not_scanned.append(
                asset_copy
            )

    return json_result({
        "threshold_days": days,
        "cutoff": cutoff.isoformat(),
        "assets_not_scanned": len(not_scanned),
        "assets": not_scanned
    })


# ============================================================
# NESSUS VULNERABILITY LISTING
# ============================================================

@mcp.tool()
def list_nessus_vulnerabilities(
    scan_id: int,
    severity: str | None = None,
    cve: str | None = None,
    host: str | None = None
) -> str:
    """
    List vulnerabilities discovered in a Nessus scan.

    Optional filters:
    - severity: info, low, medium, high, critical
    - cve: CVE identifier
    - host: hostname/IP fragment
    """

    result = nessus_request(
        "GET",
        f"/scans/{scan_id}"
    )

    if "error" in result:
        return json_result(result)

    vulnerabilities = []

    hosts = result.get(
        "hosts",
        []
    )

    severity_normalized = (
        severity.strip().lower()
        if severity
        else None
    )

    cve_normalized = (
        cve.strip().upper()
        if cve
        else None
    )

    for host_entry in hosts:

        host_id = host_entry.get(
            "host_id"
        )

        host_name = (
            host_entry.get("hostname")
            or host_entry.get("host-ip")
            or host_entry.get("host")
            or host_entry.get("name")
        )

        if (
            host
            and host_name
            and host.lower() not in str(
                host_name
            ).lower()
        ):
            continue

        host_details = nessus_request(
            "GET",
            f"/scans/{scan_id}/hosts/{host_id}"
        )

        if "error" in host_details:
            continue

        plugins = (
            host_details.get("vulnerabilities")
            or host_details.get("plugins")
            or []
        )

        for vulnerability in plugins:

            item = dict(vulnerability)

            item["scan_id"] = scan_id
            item["host_id"] = host_id
            item["host"] = host_name

            item_cves = extract_cves_from_object(
                vulnerability
            )

            item["cves"] = item_cves

            vuln_severity = str(
                vulnerability.get(
                    "severity",
                    vulnerability.get(
                        "severity_name",
                        ""
                    )
                )
            ).lower()

            if (
                severity_normalized
                and vuln_severity
                != severity_normalized
            ):
                continue

            if (
                cve_normalized
                and cve_normalized
                not in item_cves
            ):
                continue

            vulnerabilities.append(
                item
            )

    return json_result({
        "scan_id": scan_id,
        "total_vulnerabilities": len(
            vulnerabilities
        ),
        "vulnerabilities": vulnerabilities
    })


# ============================================================
# NVD CVE INTELLIGENCE
# ============================================================

@mcp.tool()
def get_cve_intelligence(
    cve_id: str
) -> str:
    """
    Retrieve detailed vulnerability intelligence from NVD.

    Includes:
    - description
    - CVSS v4
    - CVSS v3.1
    - CVSS v3.0
    - CWE
    - affected configurations
    - references
    - publication date
    - modification date
    """

    result = nvd_request(
        cve_id
    )

    if "error" in result:
        return json_result(result)

    normalized_cve = cve_id.strip().upper()

    vulnerabilities = result.get(
        "vulnerabilities",
        []
    )

    if not vulnerabilities:

        return json_result({
            "found": False,
            "cve": normalized_cve,
            "source": "NVD",
            "message": (
                "CVE was not found in NVD."
            )
        })

    cve_data = vulnerabilities[0].get(
        "cve",
        {}
    )

    descriptions = cve_data.get(
        "descriptions",
        []
    )

    description = next(
        (
            item.get("value")
            for item in descriptions
            if item.get("lang") == "en"
        ),
        None
    )

    metrics = cve_data.get(
        "metrics",
        {}
    )

    cvss_v4 = None
    cvss_v31 = None
    cvss_v30 = None

    if metrics.get("cvssMetricV40"):

        cvss_v4 = metrics[
            "cvssMetricV40"
        ][0].get(
            "cvssData",
            {}
        )

    if metrics.get("cvssMetricV31"):

        cvss_v31 = metrics[
            "cvssMetricV31"
        ][0].get(
            "cvssData",
            {}
        )

    if metrics.get("cvssMetricV30"):

        cvss_v30 = metrics[
            "cvssMetricV30"
        ][0].get(
            "cvssData",
            {}
        )

    weaknesses = []

    for weakness in cve_data.get(
        "weaknesses",
        []
    ):

        for item in weakness.get(
            "description",
            []
        ):

            if item.get("lang") == "en":

                weaknesses.append(
                    item.get("value")
                )

    references = []

    for reference in cve_data.get(
        "references",
        []
    ):

        references.append({
            "url": reference.get("url"),
            "source": reference.get("source"),
            "tags": reference.get(
                "tags",
                []
            ),
        })

    return json_result({
        "found": True,
        "source": "NVD",
        "cve": cve_data.get("id"),
        "published": cve_data.get(
            "published"
        ),
        "last_modified": cve_data.get(
            "lastModified"
        ),
        "vulnerability_status": cve_data.get(
            "vulnStatus"
        ),
        "description": description,
        "cvss": {
            "v4": cvss_v4,
            "v3.1": cvss_v31,
            "v3.0": cvss_v30,
        },
        "weaknesses": weaknesses,
        "configurations": cve_data.get(
            "configurations",
            []
        ),
        "references": references,
    })


# ============================================================
# CISA KEV
# ============================================================

@mcp.tool()
def get_cisa_kev_status(
    cve_id: str
) -> str:
    """
    Check whether a CVE is listed in the CISA Known
    Exploited Vulnerabilities catalog.
    """

    try:

        normalized_cve = validate_cve(
            cve_id
        )

    except ValueError as exc:

        return json_result({
            "error": str(exc)
        })

    catalog = get_kev_catalog()

    if "error" in catalog:
        return json_result(catalog)

    vulnerabilities = catalog.get(
        "vulnerabilities",
        []
    )

    for vulnerability in vulnerabilities:

        if (
            str(
                vulnerability.get(
                    "cveID",
                    ""
                )
            ).upper()
            == normalized_cve
        ):

            return json_result({
                "cve": normalized_cve,
                "known_exploited": True,
                "source": "CISA KEV",
                "vendor_project": vulnerability.get(
                    "vendorProject"
                ),
                "product": vulnerability.get(
                    "product"
                ),
                "vulnerability_name": vulnerability.get(
                    "vulnerabilityName"
                ),
                "date_added": vulnerability.get(
                    "dateAdded"
                ),
                "due_date": vulnerability.get(
                    "dueDate"
                ),
                "short_description": vulnerability.get(
                    "shortDescription"
                ),
                "required_action": vulnerability.get(
                    "requiredAction"
                ),
                "known_ransomware_use": vulnerability.get(
                    "knownRansomwareCampaignUse"
                ),
                "notes": vulnerability.get(
                    "notes"
                ),
            })

    return json_result({
        "cve": normalized_cve,
        "known_exploited": False,
        "source": "CISA KEV",
        "message": (
            "CVE is not currently listed "
            "in the CISA KEV catalog."
        )
    })


# ============================================================
# EPSS
# ============================================================

@mcp.tool()
def get_epss_score(
    cve_id: str
) -> str:
    """
    Get the current FIRST EPSS score and percentile
    for a CVE.
    """

    result = epss_request(
        cve_id
    )

    if "error" in result:
        return json_result(result)

    data = result.get(
        "data",
        []
    )

    if not data:

        return json_result({
            "cve": cve_id.upper(),
            "found": False,
            "source": "FIRST EPSS"
        })

    item = data[0]

    return json_result({
        "cve": item.get(
            "cve"
        ),
        "source": "FIRST EPSS",
        "date": item.get(
            "date"
        ),
        "epss": safe_float(
            item.get(
                "epss"
            )
        ),
        "percentile": safe_float(
            item.get(
                "percentile"
            )
        )
    })


# ============================================================
# EXPLOIT / POC INTELLIGENCE
# ============================================================

@mcp.tool()
def get_exploit_intelligence(
    cve_id: str
) -> str:
    """
    Search public GitHub repository metadata for exploit,
    PoC, scanner and proof-of-concept references related
    to a CVE.

    This is intelligence evidence, not proof that an exploit
    works against a specific target.
    """

    try:

        normalized_cve = validate_cve(
            cve_id
        )

    except ValueError as exc:

        return json_result({
            "error": str(exc)
        })

    headers = {
        "Accept": "application/vnd.github+json",
        "User-Agent": "Tenable-Security-MCP"
    }

    queries = [
        f"{normalized_cve} exploit",
        f"{normalized_cve} poc",
        f"{normalized_cve} proof-of-concept",
    ]

    repositories = []

    seen = set()

    for query in queries:

        try:

            response = httpx.get(
                GITHUB_API_URL,
                params={
                    "q": query,
                    "per_page": 10
                },
                headers=headers,
                timeout=30,
            )

            response.raise_for_status()

            data = response.json()

        except Exception:
            continue

        for item in data.get(
            "items",
            []
        ):

            full_name = item.get(
                "full_name"
            )

            if (
                not full_name
                or full_name in seen
            ):
                continue

            seen.add(
                full_name
            )

            repositories.append({
                "name": full_name,
                "url": item.get(
                    "html_url"
                ),
                "description": item.get(
                    "description"
                ),
                "stars": item.get(
                    "stargazers_count"
                ),
                "forks": item.get(
                    "forks_count"
                ),
                "updated_at": item.get(
                    "updated_at"
                ),
                "language": item.get(
                    "language"
                )
            })

    repositories.sort(
        key=lambda x: (
            safe_int(
                x.get("stars")
            ),
            safe_int(
                x.get("forks")
            )
        ),
        reverse=True
    )

    return json_result({
        "cve": normalized_cve,
        "source": "GitHub public repository search",
        "exploit_evidence_found": bool(
            repositories
        ),
        "repository_count": len(
            repositories
        ),
        "repositories": repositories[:20],
        "warning": (
            "Repository search results are intelligence "
            "evidence only. Presence of a repository does "
            "not prove exploitability of a specific asset."
        )
    })


# ============================================================
# COMPLETE CVE INTELLIGENCE
# ============================================================

@mcp.tool()
def get_complete_cve_intelligence(
    cve_id: str
) -> str:
    """
    Combine NVD, CISA KEV, EPSS and public exploit
    intelligence for one CVE.
    """

    try:

        normalized_cve = validate_cve(
            cve_id
        )

    except ValueError as exc:

        return json_result({
            "error": str(exc)
        })

    nvd = get_cve_intelligence(
        normalized_cve
    )

    kev = get_cisa_kev_status(
        normalized_cve
    )

    epss = get_epss_score(
        normalized_cve
    )

    exploit = get_exploit_intelligence(
        normalized_cve
    )

    try:
        nvd_data = json.loads(nvd)
    except Exception:
        nvd_data = {
            "error": "Unable to parse NVD response."
        }

    try:
        kev_data = json.loads(kev)
    except Exception:
        kev_data = {
            "error": "Unable to parse KEV response."
        }

    try:
        epss_data = json.loads(epss)
    except Exception:
        epss_data = {
            "error": "Unable to parse EPSS response."
        }

    try:
        exploit_data = json.loads(
            exploit
        )
    except Exception:
        exploit_data = {
            "error": (
                "Unable to parse exploit intelligence."
            )
        }

    cvss_score = None

    cvss_v4 = (
        nvd_data
        .get("cvss", {})
        .get("v4")
    )

    cvss_v31 = (
        nvd_data
        .get("cvss", {})
        .get("v3.1")
    )

    if cvss_v4:
        cvss_score = safe_float(
            cvss_v4.get(
                "baseScore"
            )
        )

    elif cvss_v31:
        cvss_score = safe_float(
            cvss_v31.get(
                "baseScore"
            )
        )

    epss_score = safe_float(
        epss_data.get(
            "epss"
        )
    )

    known_exploited = bool(
        kev_data.get(
            "known_exploited",
            False
        )
    )

    exploit_found = bool(
        exploit_data.get(
            "exploit_evidence_found",
            False
        )
    )

    return json_result({
        "cve": normalized_cve,
        "risk_summary": {
            "cvss": cvss_score,
            "epss": epss_score,
            "known_exploited": known_exploited,
            "public_exploit_evidence": exploit_found,
        },
        "nvd": nvd_data,
        "cisa_kev": kev_data,
        "epss": epss_data,
        "exploit_intelligence": exploit_data,
    })


# ============================================================
# RISK PRIORITIZATION ENGINE
# ============================================================

def calculate_risk_score(
    severity: str,
    cvss: float,
    epss: float,
    known_exploited: bool,
    exploit_found: bool
) -> tuple[int, str]:

    severity_weights = {
        "critical": 40,
        "high": 30,
        "medium": 18,
        "low": 8,
        "info": 0
    }

    score = severity_weights.get(
        severity.lower(),
        0
    )

    score += min(
        int(cvss * 2),
        20
    )

    score += min(
        int(epss * 20),
        20
    )

    if known_exploited:
        score += 15

    if exploit_found:
        score += 5

    score = min(
        score,
        100
    )

    if score >= 80:
        priority = "CRITICAL"

    elif score >= 60:
        priority = "HIGH"

    elif score >= 40:
        priority = "MEDIUM"

    elif score >= 20:
        priority = "LOW"

    else:
        priority = "INFO"

    return score, priority


@mcp.tool()
def prioritize_vulnerabilities(
    scan_id: int,
    max_items: int = 25
) -> str:
    """
    Prioritize vulnerabilities from a Nessus scan using:

    - Nessus severity
    - CVSS
    - EPSS
    - CISA KEV exploitation status
    - public exploit evidence

    The score is a deterministic prioritization score and
    should not be interpreted as an official vendor score.
    """

    if max_items < 1:
        max_items = 25

    scan = nessus_request(
        "GET",
        f"/scans/{scan_id}"
    )

    if "error" in scan:
        return json_result(scan)

    discovered = {}

    hosts = scan.get(
        "hosts",
        []
    )

    for host_entry in hosts:

        host_id = host_entry.get(
            "host_id"
        )

        host_name = (
            host_entry.get("hostname")
            or host_entry.get("host-ip")
            or host_entry.get("host")
            or host_entry.get("name")
        )

        host_details = nessus_request(
            "GET",
            f"/scans/{scan_id}/hosts/{host_id}"
        )

        if "error" in host_details:
            continue

        vulnerabilities = (
            host_details.get("vulnerabilities")
            or host_details.get("plugins")
            or []
        )

        for vulnerability in vulnerabilities:

            cves = extract_cves_from_object(
                vulnerability
            )

            if not cves:
                continue

            severity = str(
                vulnerability.get(
                    "severity",
                    vulnerability.get(
                        "severity_name",
                        "info"
                    )
                )
            ).lower()

            plugin_id = vulnerability.get(
                "plugin_id"
            )

            plugin_name = (
                vulnerability.get(
                    "plugin_name"
                )
                or vulnerability.get(
                    "name"
                )
                or vulnerability.get(
                    "plugin"
                )
            )

            for cve in cves:

                key = (
                    cve,
                    str(host_name)
                )

                if key in discovered:
                    continue

                discovered[key] = {
                    "cve": cve,
                    "host": host_name,
                    "host_id": host_id,
                    "plugin_id": plugin_id,
                    "plugin_name": plugin_name,
                    "nessus_severity": severity,
                }

    prioritized = []

    for item in discovered.values():

        cve = item["cve"]

        try:

            nvd = json.loads(
                get_cve_intelligence(cve)
            )

        except Exception:

            nvd = {}

        try:

            kev = json.loads(
                get_cisa_kev_status(cve)
            )

        except Exception:

            kev = {}

        try:

            epss = json.loads(
                get_epss_score(cve)
            )

        except Exception:

            epss = {}

        cvss = 0.0

        cvss_v4 = (
            nvd
            .get("cvss", {})
            .get("v4")
        )

        cvss_v31 = (
            nvd
            .get("cvss", {})
            .get("v3.1")
        )

        if cvss_v4:
            cvss = safe_float(
                cvss_v4.get(
                    "baseScore"
                )
            )

        elif cvss_v31:
            cvss = safe_float(
                cvss_v31.get(
                    "baseScore"
                )
            )

        epss_score = safe_float(
            epss.get(
                "epss"
            )
        )

        known_exploited = bool(
            kev.get(
                "known_exploited",
                False
            )
        )

        exploit_found = False

        try:

            exploit = json.loads(
                get_exploit_intelligence(cve)
            )

            exploit_found = bool(
                exploit.get(
                    "exploit_evidence_found",
                    False
                )
            )

        except Exception:
            exploit_found = False

        score, priority = calculate_risk_score(
            item["nessus_severity"],
            cvss,
            epss_score,
            known_exploited,
            exploit_found
        )

        item.update({
            "cvss": cvss,
            "epss": epss_score,
            "cisa_kev": known_exploited,
            "public_exploit_evidence": exploit_found,
            "risk_score": score,
            "priority": priority,
        })

        prioritized.append(
            item
        )

    prioritized.sort(
        key=lambda x: x.get(
            "risk_score",
            0
        ),
        reverse=True
    )

    return json_result({
        "scan_id": scan_id,
        "risk_model": {
            "description": (
                "Deterministic prioritization using "
                "Nessus severity, CVSS, EPSS, CISA KEV "
                "and public exploit evidence."
            ),
            "maximum_score": 100
        },
        "total_cve_host_pairs": len(
            prioritized
        ),
        "results": prioritized[
            :max_items
        ]
    })


# ============================================================
# EMERGING THREAT / ZERO-DAY ANALYSIS
# ============================================================

@mcp.tool()
def analyze_emerging_threats(
    scan_id: int,
    max_items: int = 25
) -> str:
    """
    Identify high-priority emerging vulnerability signals
    in a Nessus scan.

    Signals include:
    - CISA KEV
    - high EPSS
    - public exploit evidence
    - high CVSS
    - critical/high Nessus severity

    This does NOT claim that an unknown zero-day has been
    discovered. It identifies vulnerabilities requiring
    urgent investigation.
    """

    prioritized_result = prioritize_vulnerabilities(
        scan_id,
        max_items=max_items
    )

    try:

        prioritized = json.loads(
            prioritized_result
        )

    except Exception:

        return json_result({
            "error": (
                "Unable to process prioritization results."
            )
        })

    candidates = []

    for item in prioritized.get(
        "results",
        []
    ):

        signals = []

        if item.get(
            "cisa_kev"
        ):
            signals.append(
                "CISA_KNOWN_EXPLOITATION"
            )

        if safe_float(
            item.get("epss")
        ) >= 0.5:

            signals.append(
                "HIGH_EPSS"
            )

        if item.get(
            "public_exploit_evidence"
        ):

            signals.append(
                "PUBLIC_EXPLOIT_EVIDENCE"
            )

        if safe_float(
            item.get("cvss")
        ) >= 9.0:

            signals.append(
                "CRITICAL_CVSS"
            )

        if str(
            item.get(
                "nessus_severity",
                ""
            )
        ).lower() in {
            "critical",
            "high"
        }:

            signals.append(
                "HIGH_NESSUS_SEVERITY"
            )

        if signals:

            candidate = dict(item)

            candidate[
                "threat_signals"
            ] = signals

            candidate[
                "urgent_investigation"
            ] = (
                len(signals) >= 2
                or item.get(
                    "cisa_kev",
                    False
                )
            )

            candidates.append(
                candidate
            )

    return json_result({
        "scan_id": scan_id,
        "analysis": (
            "Emerging-threat signal analysis. "
            "These results are candidates for urgent "
            "investigation and are not proof of an "
            "unknown zero-day."
        ),
        "candidate_count": len(
            candidates
        ),
        "candidates": candidates
    })


# ============================================================
# NORMALIZED / RAG-READY SECURITY CONTEXT
# ============================================================

@mcp.tool()
def build_security_context(
    cve_id: str
) -> str:
    """
    Build a normalized security-intelligence record suitable
    for downstream RAG or LLM reasoning.
    """

    complete = get_complete_cve_intelligence(
        cve_id
    )

    try:

        data = json.loads(
            complete
        )

    except Exception:

        return json_result({
            "error": (
                "Unable to build security context."
            )
        })

    nvd = data.get(
        "nvd",
        {}
    )

    kev = data.get(
        "cisa_kev",
        {}
    )

    epss = data.get(
        "epss",
        {}
    )

    exploit = data.get(
        "exploit_intelligence",
        {}
    )

    cvss = (
        data
        .get("risk_summary", {})
        .get("cvss")
    )

    epss_score = (
        data
        .get("risk_summary", {})
        .get("epss")
    )

    context = {
        "document_type": "security_vulnerability",
        "document_id": cve_id.upper(),
        "title": (
            nvd.get(
                "cve",
                cve_id.upper()
            )
        ),
        "description": nvd.get(
            "description"
        ),
        "published": nvd.get(
            "published"
        ),
        "last_modified": nvd.get(
            "last_modified"
        ),
        "cvss": cvss,
        "epss": epss_score,
        "known_exploited": kev.get(
            "known_exploited",
            False
        ),
        "known_ransomware_use": kev.get(
            "known_ransomware_use"
        ),
        "public_exploit_evidence": exploit.get(
            "exploit_evidence_found",
            False
        ),
        "weaknesses": nvd.get(
            "weaknesses",
            []
        ),
        "references": nvd.get(
            "references",
            []
        ),
        "security_signals": {
            "cisa_kev": kev.get(
                "known_exploited",
                False
            ),
            "high_epss": (
                safe_float(
                    epss_score
                ) >= 0.5
            ),
            "public_exploit": exploit.get(
                "exploit_evidence_found",
                False
            ),
            "critical_cvss": (
                safe_float(
                    cvss
                ) >= 9.0
            )
        }
    }

    return json_result(
        context
    )


# ============================================================
# TENABLE VULNERABILITY MANAGEMENT / CLOUD
# ============================================================

@mcp.tool()
def get_tenable_cloud_server_info() -> str:
    """
    Get information from the configured Tenable cloud
    environment.

    Requires TENABLE_CLOUD_ACCESS_KEY and
    TENABLE_CLOUD_SECRET_KEY.
    """

    result = tenable_cloud_request(
        "GET",
        "/server/properties"
    )

    return json_result(result)


@mcp.tool()
def list_tenable_cloud_assets(
    limit: int = 100
) -> str:
    """
    List assets from Tenable Vulnerability Management.
    """

    limit = max(
        1,
        min(
            limit,
            1000
        )
    )

    result = tenable_cloud_request(
        "GET",
        "/workbenches/assets",
        params={
            "limit": limit
        }
    )

    return json_result(result)


@mcp.tool()
def list_tenable_cloud_vulnerabilities(
    limit: int = 100
) -> str:
    """
    List vulnerabilities from Tenable Vulnerability Management.
    """

    limit = max(
        1,
        min(
            limit,
            1000
        )
    )

    result = tenable_cloud_request(
        "GET",
        "/workbenches/vulnerabilities",
        params={
            "limit": limit
        }
    )

    return json_result(result)


@mcp.tool()
def get_tenable_cloud_vulnerability(
    plugin_id: str
) -> str:
    """
    Get vulnerability information from Tenable
    Vulnerability Management.
    """

    result = tenable_cloud_request(
        "GET",
        f"/workbenches/vulnerabilities/{plugin_id}"
    )

    return json_result(result)


@mcp.tool()
def get_tenable_cloud_asset(
    asset_uuid: str
) -> str:
    """
    Get details for a Tenable Vulnerability Management asset.
    """

    result = tenable_cloud_request(
        "GET",
        f"/workbenches/assets/{asset_uuid}"
    )

    return json_result(result)


# ============================================================
# UNIFIED CVE SEARCH
# ============================================================

@mcp.tool()
def search_security_intelligence(
    cve_id: str
) -> str:
    """
    Unified security intelligence lookup.

    Searches:
    - NVD
    - CISA KEV
    - EPSS
    - public exploit intelligence
    - normalized security context
    """

    return get_complete_cve_intelligence(
        cve_id
    )


# ============================================================
# PROJECT HEALTH / CAPABILITY INFORMATION
# ============================================================

@mcp.tool()
def get_mcp_capabilities() -> str:
    """
    Show the capabilities available through the Tenable
    Security MCP server.
    """

    return json_result({
        "name": "Tenable Security MCP",
        "version": "1.0",
        "capabilities": {
            "nessus": True,
            "asset_scan_age": True,
            "vulnerability_analysis": True,
            "nvd": True,
            "cisa_kev": True,
            "epss": True,
            "exploit_intelligence": True,
            "combined_cve_intelligence": True,
            "risk_prioritization": True,
            "emerging_threat_analysis": True,
            "rag_ready_security_context": True,
            "tenable_vulnerability_management": True,
        },
        "data_sources": [
            "Tenable Nessus",
            "NVD",
            "CISA KEV",
            "FIRST EPSS",
            "GitHub public repository metadata",
            "Tenable Vulnerability Management"
        ],
        "architecture": (
            "Single MCP server with local Nessus, "
            "external security intelligence and "
            "Tenable cloud capabilities."
        )
    })


# ============================================================
# SERVER START
# ============================================================

if __name__ == "__main__":
    mcp.run()
