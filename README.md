# 🔐 Tenable Security MCP
## AI-Assisted Vulnerability Management with Claude Desktop

---

## 📋 Executive Summary

**Tenable Security MCP** is a cutting-edge **Model Context Protocol (MCP) server** that unifies vulnerability management intelligence, enabling security teams to leverage AI for rapid threat prioritization and remediation planning.

🎯 **Transform this:**
```
Nessus → CVE → CVSS → EPSS → CISA KEV → Exploit Research → Risk Assessment
```

✨ **Into this:**
```
Claude Desktop → Tenable Security MCP → Unified Intelligence → Actionable Insights
```

---

## 🎯 Core Capabilities

### 🔍 Nessus Operations
- ✅ Retrieve server information and scan details
- ✅ List, launch, and manage scans
- ✅ Access granular host and vulnerability data
- ✅ Manage policies, folders, and agent deployments

### 🛡️ Vulnerability Intelligence
- ✅ Enrich findings with CVE details (NVD)
- ✅ Cross-reference CVSS scores & EPSS probabilities
- ✅ Check CISA Known Exploited Vulnerabilities (KEV)
- ✅ Aggregate public exploit and PoC intelligence

### 📊 Risk Prioritization Engine
Intelligent correlation across multiple signals:
- 🔴 Nessus severity ratings
- 📈 CVSS base & temporal scores
- ⚡ EPSS exploitation probability
- 🚨 CISA KEV status
- 💣 Public exploit availability
- 🏢 Asset context & criticality

### 💬 Example Queries
```
"Analyze my latest scan and list critical findings"
"Get complete intelligence for CVE-2024-3094"
"Which vulnerabilities require urgent remediation?"
"Prioritize findings using severity, CVSS, EPSS, and exploit data"
"Create a remediation roadmap for high-risk assets"
```

---

## 🏗️ Architecture Overview

### 🔗 Integration Model
```
┌─────────────────────────────────────────────────┐
│         Claude Desktop Application              │
└──────────────────┬──────────────────────────────┘
                   │
                   ▼
┌─────────────────────────────────────────────────┐
│   Tenable Security MCP Server (Python)          │
└──┬─────────────┬──────────────┬────────────────┐
   │             │              │                │
   ▼             ▼              ▼                ▼
Nessus      NVD/CVE        EPSS/CISA        Exploit
(Local)     (Public)       (Public)         Intelligence
```

### 🔒 Security Design
- 🟢 **Nessus stays local** - No public internet exposure required
- 🟢 **MCP handles external APIs** - Isolated API credential management
- 🟢 **Zero trust** - All data validated and contextualized
- 🟢 **Analyst-in-the-loop** - AI assists, humans decide

---

## 🚀 Quick Start

### 📦 Prerequisites
- ✅ Claude Desktop (latest version)
- ✅ Nessus Essentials or Professional/Expert
- ✅ Nessus API keys (access key + secret key)
- ✅ Git installed

---

## 🔧 Installation Guide

### **Step 1️⃣: Clone Repository**
```bash
git clone https://github.com/kasireddy-sec/tenable-security-mcp.git
cd tenable-security-mcp
```

### **Step 2️⃣: Build Extension**

#### **✅ Option A: GitHub Actions (Recommended) 🚀**

1. **Push your changes** to GitHub (if you made local edits):
   ```bash
   git add -A && git commit -m "update" && git push origin your-branch
   ```

2. **Navigate to GitHub Actions:**
   - Go to your repository on GitHub
   - Click **"Actions"** in the top menu
   - Select **"build.yml"** from the workflow list

3. **Trigger the workflow:**
   - Click the green **"Run workflow"** button
   - Choose the branch to run on (default is `main`)
   - ✅ Tip: This automatically runs tests and builds the extension

4. **Wait for completion:**
   - Monitor the run progress and logs in the Actions UI
   - Build typically completes in 2-3 minutes ⏱️

5. **Download the artifact:** 🎉
   - When the workflow finishes, expand the **"Artifacts"** section
   - Download `extension.mcpb` directly from the workflow run page

**Why this is recommended:**
- ✅ Zero local setup required
- ✅ Reproducible builds with full CI logs
- ✅ Easy artifact download from web UI
- ✅ No dependency issues

#### **🔧 Option B: Build Locally (For Advanced Users)**

```bash
# Install MCP build tools
pip install -r requirements.txt

# Build the extension
mcp build

# Verify output
ls dist/extension.mcpb
```

### **Step 3️⃣: Install to Claude Desktop**
1. Open **Claude Desktop**
2. Navigate to: **Settings → Extensions → Advanced Settings**
3. Click **Install Extension**
4. Select `extension.mcpb` file (from Step 2)
5. Enable the extension ✅

### **Step 4️⃣: Configure Nessus**
1. Go to: **Settings → Extensions → Tenable Security MCP**
2. Click **Configure** and enter:
   - **Nessus URL**: `https://localhost:8834`
   - **API Access Key**: `your_access_key_here`
   - **API Secret Key**: `your_secret_key_here`

### **Step 5️⃣: Verify Installation**
```bash
# In Claude Desktop, test with:
"Get my Nessus server information"
```

✅ You should receive live Nessus data!

---

## 📊 Practical Security Workflows

### 🔴 Critical Incident Response
```
"Analyze my latest scan and list critical findings with affected hosts"
```
→ Immediate visibility into high-risk assets

### 🔍 CVE Deep Dive
```
"Get complete intelligence for CVE-2024-3094: CVSS, EPSS, CISA KEV, and exploit status"
```
→ Comprehensive threat context in seconds

### 📈 Smart Prioritization
```
"Which 5 vulnerabilities pose highest risk based on EPSS, exploitability, and asset criticality?"
```
→ Data-driven remediation sequencing

### 🗓️ Coverage Assessment
```
"Identify assets that haven't been scanned in the last 7 days"
```
→ Risk visibility across your estate

### 🛠️ Remediation Planning
```
"Create a prioritized roadmap for findings above CVSS 7.0 with CISA KEV or public exploits"
```
→ Structured remediation strategy

---

## 🏢 Technology Stack

| Component | Technology |
|-----------|-----------|
| **Language** | Python 3.9+ |
| **Framework** | MCP Python SDK |
| **Transport** | HTTPS/REST |
| **APIs** | Nessus, NVD, EPSS, CISA KEV, Exploit Intelligence |
| **Build Tool** | GitHub Actions + MCP Build |

---

## 📁 Project Structure

```
tenable-security-mcp/
├── 📂 .github/workflows/
│   ├── test.yml              # Automated testing pipeline
│   └── build.yml             # MCPB packaging & release
├── 📂 extension/
│   ├── manifest.json         # Extension metadata
│   ├── pyproject.toml        # Dependencies & configuration
│   └── 📂 src/
│       └── server.py         # MCP server implementation
├── pyproject.toml            # Project configuration
└── README.md                 # This file
```

---

## 🔄 Build & Release Pipeline

```
┌─────────────────────────────────────────────────┐
│       Developer Pushes to GitHub                │
└────────────────────┬────────────────────────────┘
                     │
                     ▼
        ┌────────────────────────────┐
        │  GitHub Actions Triggered  │
        └────┬───────────────────┬───┘
             │                   │
             ▼                   ▼
        ┌──────────┐      ┌──────────────┐
        │Run Tests │      │ Build MCPB   │
        └──────────┘      └──────┬───────┘
                                 │
                     ┌───────────▼────────────┐
                     │ extension.mcpb Created │
                     └───────────┬────────────┘
                                 │
                     ┌───────────▼───────────────┐
                     │ Download from Workflow    │
                     │ Install to Claude        │
                     └──────────────────────────┘
```

---

## ⚠️ Known Issues & Solutions

### 🪟 Windows MSIX Installation Issue

**Problem:**
```
can't open file ... src/server.py
[Errno 2] No such file or directory
```

**Root Cause:** MSIX resolves MCP server paths incorrectly

**Solution:** Use standard Claude Desktop installer (not MSIX/enterprise)

✅ **Recommended**: Standard installer for Windows users

### 🐍 UV / Python Permission Denied

**Problem:**
```
Access is denied (installing dependencies)
```

**Root Cause:** Microsoft Store Python has restricted write permissions

**Solution:** Extension uses isolated user-level UV environment

✅ **No manual action needed** - automatic fallback enabled

---

## 🔒 Security Best Practices

### ✅ **DO**
- 🟢 Store Nessus API credentials in configuration (never commit to repo)
- 🟢 Use standard Claude Desktop installer
- 🟢 Validate Claude's recommendations before production changes
- 🟢 Treat exploit intelligence as supporting evidence
- 🟢 Maintain audit logs of all vulnerability assessments

### ❌ **DON'T**
- 🔴 Commit API credentials to GitHub
- 🔴 Expose local Nessus to public internet
- 🔴 Scan systems without proper authorization
- 🔴 Treat AI recommendations as definitive without analyst review
- 🔴 Share sensitive finding details in untrusted environments

---

## 🤝 Contributing

We welcome contributions from the security community!

### Development Workflow
```bash
# 1. Fork repository
git clone https://github.com/YOUR-USERNAME/tenable-security-mcp.git

# 2. Create feature branch
git checkout -b feature/your-feature-name

# 3. Make changes to extension/src/server.py
# ... your code changes ...

# 4. Test locally
mcp build
mcp run

# 5. Commit and push
git add .
git commit -m "Add: your feature description"
git push origin feature/your-feature-name

# 6. Submit Pull Request
# GitHub Actions will automatically build and test
```

**Contribution Guidelines:**
- 📋 Follow Python PEP 8 style guide
- 🧪 Include test cases for new features
- 📝 Update documentation
- ✅ Ensure GitHub Actions passes all checks

---

## 📄 License

**MIT License** - Open source and free to use

See [LICENSE](LICENSE) file for complete details

---

## 🎯 Vision

**Transform vulnerability management from reactive firefighting to strategic risk management.**

- 🔍 **Faster Analysis** - Minutes instead of hours
- 💡 **Better Decisions** - AI-assisted prioritization
- 📉 **Reduced Risk** - Intelligent remediation
- ⏱️ **Increased Velocity** - Automate the routine

---

## 📞 Support & Resources

| Resource | Link |
|----------|------|
| **GitHub Issues** | [Report Bug / Request Feature](../../issues) |
| **Documentation** | README.md (you are here) |
| **Tenable Docs** | [Nessus API Reference](https://docs.tenable.com/nessus) |
| **CISA KEV** | [Known Exploited Vulnerabilities](https://cisa.gov/known-exploited-vulnerabilities) |
| **EPSS** | [Exploit Prediction Scoring System](https://www.first.org/epss) |

---

<div align="center">

### 🚀 Built to Turn Raw Nessus Findings into Actionable Security Intelligence

**Tenable Security MCP** → Faster Analysis → Better Decisions → Reduced Risk

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Python 3.9+](https://img.shields.io/badge/Python-3.9+-blue.svg)](https://www.python.org/)

**Made for Security Professionals | Built on MCP | Powered by Claude AI**

</div>
