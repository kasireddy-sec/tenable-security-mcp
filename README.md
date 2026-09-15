# Tenable Security MCP

**AI-Assisted Vulnerability Management with Claude Desktop**

Tenable Security MCP is an MCP (Model Context Protocol) server that connects Claude Desktop with Tenable Nessus and security intelligence sources, enabling vulnerability management teams to interact with vulnerability data using natural language.

Instead of manually switching between Nessus, CVE databases, EPSS, CISA KEV, and exploit intelligence sources, ask Claude:

> "Prioritize the vulnerabilities in my latest Nessus scan using severity, CVSS, EPSS, CISA KEV and exploit intelligence."

Claude uses the MCP tools to retrieve and correlate relevant information across all sources and provide a security-focused response.

---

## The Problem

Vulnerability Management analysts spend significant time in repetitive information gathering:

```
Nessus → CVE → CVSS → EPSS → CISA KEV → Exploit Research → Risk Assessment → Prioritization
```

This manual correlation across multiple disconnected systems delays decision-making and reduces remediation velocity.

---

## The Solution

Tenable Security MCP unifies the entire workflow:

```
Claude Desktop
    ↓
Tenable Security MCP
    ├── Nessus
    ├── NVD / CVE Intelligence
    ├── CISA KEV
    ├── EPSS
    └── Exploit Intelligence
    ↓
Correlated Intelligence → Actionable Insights
```

**Result**: Vulnerability analysts spend more time on validation and remediation decisions, less time on data collection.

---

## What It Can Do

### Nessus Operations
- Retrieve server information and scan details
- List and launch scans
- Access host and vulnerability data
- Manage policies, folders, and agents

### Vulnerability Intelligence
- Enrich Nessus findings with CVE details
- Cross-reference CVSS scores and EPSS probabilities
- Check CISA Known Exploited Vulnerabilities status
- Aggregate public exploit and PoC intelligence

### Risk Prioritization
Combine multiple signals for intelligent prioritization:
- Nessus severity
- CVSS score
- EPSS probability
- CISA KEV status
- Exploit availability
- Affected assets and context

### Example Queries
```
"List vulnerabilities from my latest Nessus scan"
"Show all critical findings and affected hosts"
"Which vulnerabilities require urgent remediation?"
"Get complete intelligence for CVE-2024-3094"
"Prioritize findings using severity, CVSS, EPSS, and exploit data"
```

---

## Architecture

**Local Nessus Deployment**
```
Claude Desktop ─── MCP ─── Tenable Security MCP ─── HTTPS/REST ─── Nessus (localhost:8834)
```

**Intelligence Enrichment**
```
Nessus Finding
    ↓
CVE Identified
    ├── NVD (CVSS)
    ├── EPSS (Exploit Probability)
    ├── CISA KEV (Known Exploitation)
    └── Exploit Intelligence
    ↓
Security Context + Risk Score
    ↓
Claude Response
```

**Key Design Principle**: Nessus remains local and never needs public internet exposure. The MCP server handles all external API calls.

---

## Getting Started

### Prerequisites
- Claude Desktop
- Nessus Essentials or Professional/Expert
- Nessus API access and secret keys
- `extension.mcpb` artifact

**No need to clone, configure Python, manage environments, or manually start services.**

### Installation (3 Steps)

**Step 1: Download**
- Get `extension.mcpb` from [GitHub Releases](https://github.com/kasireddy-sec/tenable-security-mcp/releases)

**Step 2: Install**
- Open Claude Desktop → Settings → Extensions → Advanced Settings → Install Extension
- Select the downloaded `extension.mcpb`

**Step 3: Configure**
- Settings → Extensions → Tenable Security MCP → Configure
- Enter:
  - Nessus URL: `https://localhost:8834`
  - API Access Key
  - API Secret Key

### Verify Installation
```
User: "Get my Nessus server information"
Claude: [Returns live Nessus data]
```

---

## Practical Workflows

### Scan Analysis
```
"Analyze my latest scan and list critical findings with affected hosts"
```

### CVE Intelligence
```
"Get complete intelligence for CVE-2024-3094: CVSS, EPSS, CISA KEV, and exploit status"
```

### Risk Prioritization
```
"Which 5 vulnerabilities in my scan pose the highest risk based on EPSS, exploitability, and asset criticality?"
```

### Coverage Assessment
```
"Identify assets that haven't been scanned in the last 7 days"
```

### Remediation Planning
```
"Create a prioritized remediation roadmap for findings above CVSS 7.0 with CISA KEV or public exploits"
```

---

## How It Works Under the Hood

### Technology Stack
- **Language**: Python 3.9+
- **MCP Framework**: MCP Python SDK
- **Transport**: HTTP/HTTPS
- **APIs Integrated**:
  - Nessus REST API
  - National Vulnerability Database (NVD)
  - CISA Known Exploited Vulnerabilities
  - EPSS (Exploit Prediction Scoring System)
  - Public exploit intelligence sources

### Extension Distribution
```
Python MCP Server → MCPB Package → Claude Desktop Extension → Users
```

The `.mcpb` format encapsulates the server runtime, dependencies, and configuration—users just download and install.

---

## Windows Considerations

### Standard Installation
Use the standard Claude Desktop installer (not MSIX/Enterprise package) for individual Windows users.

### Automatic Environment Management
- UV runtime handles Python environment isolation
- Dependencies install to user-level environment
- No manual Python setup required

---

## Security & Best Practices

✅ **Do**
- Keep Nessus API credentials in configuration (not code)
- Use the standard Claude Desktop installer
- Validate Claude's recommendations before production action
- Treat exploit intelligence as supporting evidence, not proof

❌ **Don't**
- Commit API credentials to GitHub
- Expose local Nessus to the public internet
- Scan systems you don't have authorization for
- Treat AI recommendations as definitive without analyst review

---

## Project Structure

```
tenable-security-mcp/
├── .github/workflows/
│   ├── test.yml          # Automated testing
│   └── build.yml         # MCPB packaging & release
├── extension/
│   ├── manifest.json     # Extension metadata
│   ├── pyproject.toml    # Dependencies & config
│   └── src/server.py     # MCP server implementation
├── pyproject.toml
└── README.md
```

The extension builds into a single `extension.mcpb` artifact for distribution.

---

## Build & Release Pipeline

```
Code Push → GitHub Actions
           ├── Run Tests
           └── Build MCPB
               ↓
           GitHub Release
               ↓
           extension.mcpb (downloadable artifact)
               ↓
           Users: Download → Install → Use
```

Updates flow seamlessly: modify code → push → new artifact → users download updated extension.

---

## Future Capabilities

- **Tenable Cloud Support**: Extend to Tenable Vulnerability Management / Tenable Cloud
- **Multi-Scanner**: Support additional vulnerability scanners
- **Automated Workflows**: Trigger remediation actions directly from Claude
- **Custom Intelligence**: Integrate proprietary threat feeds
- **Team Collaboration**: Share prioritization and remediation plans

---

## Why This Approach

| Traditional | Tenable Security MCP |
|---|---|
| Manual switching between 5+ systems | Single natural language interface |
| 15-20 min per vulnerability assessment | 2-3 min with AI correlation |
| Copy/paste data across platforms | Automatic intelligence aggregation |
| Repetitive research | Focus on validation & decisions |
| Individual analyst workflow | Team-aligned prioritization |

---

## Contributing

This is an open-source project. Contributions welcome:

1. Fork the repository
2. Create a feature branch
3. Make changes to `extension/src/server.py`
4. Test locally
5. Submit a pull request

---

## Support

- **Issues**: [GitHub Issues](https://github.com/kasireddy-sec/tenable-security-mcp/issues)
- **Discussions**: [GitHub Discussions](https://github.com/kasireddy-sec/tenable-security-mcp/discussions)
- **Documentation**: See docs/ directory

---

## Disclaimer

This tool is for authorized vulnerability assessments only. Ensure you have proper authorization before accessing any Nessus or Tenable infrastructure. Unauthorized access to security tools and vulnerability data may violate laws and regulations.

---

## License

MIT License - see [LICENSE](LICENSE) file for details.

---

**Built to turn raw Nessus findings into actionable security intelligence using MCP and AI.**

🔍 **Tenable Security MCP** → Faster Analysis → Better Decisions → Reduced Risk
