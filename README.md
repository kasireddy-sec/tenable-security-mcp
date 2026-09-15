# Tenable Security MCP

**AI-Assisted Vulnerability Management with Claude Desktop**

Tenable Security MCP is an MCP (Model Context Protocol) server that connects Claude Desktop with Tenable Nessus and security intelligence sources, enabling vulnerability management teams to interac[...]

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
- Git

---

## Installation

### Step 1: Clone the Repository

```bash
git clone https://github.com/kasireddy-sec/tenable-security-mcp.git
cd tenable-security-mcp
```

### Step 2: Build the Extension

The project uses GitHub Actions to automatically build the `.mcpb` extension artifact.

✅ Option A — Use GitHub Actions (Recommended) 🚀

1. Push your changes or any branch to GitHub (if you made local edits):
   - git add -A && git commit -m "update" && git push origin your-branch
2. Go to the repository on GitHub → Click "Actions" in the top menu.
3. Select the "build.yml" workflow from the list.
4. Click the green "Run workflow" button and choose the branch to run on (default is main).  
   - Tip: This runs tests and builds the extension automatically.
5. Wait a few minutes for the workflow to complete. You’ll see the run progress and logs in the Actions UI.
6. When the run finishes, expand the "Artifacts" section and download extension.mcpb. 🎉
   - The artifact will be named `extension.mcpb` and is available directly from the workflow run page.

Why this is recommended:
- Zero local setup required ✅
- Reproducible builds and CI logs ✅
- Easy artifact download from the web UI ✅

🔧 Option B — Build Locally (for advanced users)

```bash
# Install MCP build tools
pip install -r requirements.txt

# Build the extension
mcp build

# The extension.mcpb will be generated in dist/
ls dist/extension.mcpb
```

### Step 3: Install into Claude Desktop

1. Open Claude Desktop
2. Go to: **Settings** → **Extensions** → **Advanced Settings** → **Install Extension**
3. Select the `extension.mcpb` file (from Step 2)
4. Enable the extension ✅

### Step 4: Configure Nessus

1. Go to: **Settings** → **Extensions** → **Tenable Security MCP** → **Configure**
2. Enter:
   - **Nessus URL**: `https://localhost:8834`
   - **API Access Key**: Your Nessus API key
   - **API Secret Key**: Your Nessus API secret

### Step 5: Verify Installation

Open Claude and run:
```
"Get my Nessus server information"
```

Claude should return live data from your Nessus instance.

---

## Workflow: Clone → Build → Install

```
Clone Repository
    ↓
git clone https://github.com/kasireddy-sec/tenable-security-mcp.git
    ↓
Trigger GitHub Actions (or build locally)
    ↓
mcp build  (or Actions workflow)
    ↓
Download extension.mcpb artifact
    ↓
Install into Claude Desktop
    ↓
Configure Nessus credentials
    ↓
Start using with Claude
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

## Technology Stack

- **Language**: Python 3.9+
- **MCP Framework**: MCP Python SDK
- **Transport**: HTTP/HTTPS
- **APIs Integrated**:
  - Nessus REST API
  - National Vulnerability Database (NVD)
  - CISA Known Exploited Vulnerabilities
  - EPSS (Exploit Prediction Scoring System)
  - Public exploit intelligence sources

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

The GitHub Actions workflow automatically builds the `.mcpb` artifact from the `extension/` directory.

---

## Build Pipeline

```
Push to GitHub
    ↓
GitHub Actions Triggered
    ├── Run Tests
    └── Build MCPB
        ↓
    Artifact Created (extension.mcpb)
        ↓
    User Downloads from Workflow Run
        ↓
    Installs into Claude Desktop
```

---

## ⚠️ Known Installation Issues

### Windows MSIX Installation Issue

**Problem**: When using the MSIX/enterprise installation of Claude Desktop, the extension may fail with:
```
can't open file ... src/server.py
[Errno 2] No such file or directory
```

**Cause**: MSIX resolves the MCP server's execution path incorrectly, even though extension files are present.

**Solution**: Use the **standard Claude Desktop installer** instead of MSIX/enterprise package for individual Windows users.

**Flow that fails**:
```
MSIX Installation
    ↓
UV Environment Created
    ↓
Dependencies Installed
    ↓
Server Files Present
    ↓
Incorrect Windows Path Resolution
    ↓
MCP Server Fails to Start
```

**Do not add Windows-specific paths** like `C:\Users\<username>\` to the project. The `.mcpb` package must remain portable across systems.

---

### UV / Python Permission Issue

**Problem**: UV fails to install dependencies into protected Microsoft Store Python installations with:
```
Access is denied
```

**Cause**: Microsoft Store Python has restricted write permissions.

**Solution**: The extension is configured to use an isolated user-level UV environment instead.

**Runtime Model**:
```
Claude Desktop
    ↓
UV Runtime
    ↓
User-level Python Environment
    ↓
MCP Dependencies
    ↓
Tenable Security MCP
```

Users should not need to manually create or manage this environment.

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

## Contributing

This is an open-source project. Contributions welcome:

1. Fork the repository
2. Create a feature branch
3. Make changes to `extension/src/server.py`
4. Test locally with `mcp build && mcp run`
5. Commit and push
6. Submit a pull request

The GitHub Actions workflow will automatically build and test your changes.

---

## License

MIT License - see [LICENSE](LICENSE) file for details.

---

**Built to turn raw Nessus findings into actionable security intelligence using MCP and AI.**

🔍 **Tenable Security MCP** → Faster Analysis → Better Decisions → Reduced Risk
