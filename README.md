# FlowSec

> A Python security tool that scans CI/CD pipeline configurations for attack vectors across GitHub Actions, GitLab CI, and Azure DevOps. Every finding maps to a MITRE ATT&CK technique and OWASP CICD Top 10 category.
>
> The pipeline is the attack surface. FlowSec treats it that way.

[![PyPI version](https://badge.fury.io/py/flowsec.svg)](https://badge.fury.io/py/flowsec)


[![Open in GitHub Codespaces](https://github.com/codespaces/badge.svg)](https://codespaces.new/VanshBhardwaj1945/FlowSec)

**[Full documentation](docs/FULL_README.md)**

**Install from PyPI:**
```bash
pip install flowsec
flowsec scan --repo owner/repo
```

**Or run from source:**
```bash
git clone https://github.com/VanshBhardwaj1945/FlowSec.git
cd FlowSec
python3 -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
cp .env.example .env
# Add your GITHUB_TOKEN to .env

```
---

## CLI

```bash
# GitHub Actions — remote repo
flowsec scan --repo VanshBhardwaj1945/cloud-resume-challenge-azure

# GitHub Actions — local file
flowsec scan --file .github/workflows/ci.yml

# GitLab CI
flowsec scan --gitlab .gitlab-ci.yml

# Azure DevOps
flowsec scan --azure azure-pipelines.yml

# HTML report
flowsec scan --repo owner/repo --output report.html

# AI attack narratives
flowsec scan --repo owner/repo --ai

# Pipeline gate
flowsec scan --repo owner/repo --fail-on critical

# Everything at once
flowsec scan --repo owner/repo --ai --output report.html --fail-on high
```

---

## Status

| Component | Status |
|---|---|
| Rule engine — BaseRule, Finding, Severity | Complete |
| YAML parser with line number tracking | Complete |
| 17 security rules FS001-FS013 | Complete |
| MITRE ATT&CK + OWASP CICD Top 10 mapping | Complete |
| Platform-aware rule engine | Complete |
| GitHub Actions scanner — API and local file | Complete |
| GitLab CI scanner | Complete |
| Azure DevOps scanner | Complete |
| CLI — all flags | Complete |
| Rich terminal output with risk score | Complete |
| HTML report with filtering, PDF export | Complete |
| AI attack narratives with local caching | Complete |
| Line number tracking | Complete |
| Pipeline gate --fail-on | Complete |
| GitHub Codespace config | Complete |
| PyPI publish | Complete |
