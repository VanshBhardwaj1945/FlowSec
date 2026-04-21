# FlowSec

> A Python security tool that connects to GitHub, pulls CI/CD pipeline configs, and runs a library of security rules against them to find attack vectors. Every finding maps to a MITRE ATT&CK technique.
>
> The pipeline is the attack surface. FlowSec treats it that way.

**[Full documentation](docs/FULL_README.md)**

---

## What it catches

| ID | Rule | Severity | MITRE |
|---|---|---|---|
| FS001 | Hardcoded Secret — Plaintext Credential in Workflow | CRITICAL | T1552.001 |
| FS002 | Unpinned Action — Supply Chain Attack Vector | CRITICAL | T1195.001 |
| FS003 | Excessive Permissions — Overprivileged Workflow Token | HIGH | T1078 |
| FS004 | Missing OIDC — Long-Lived Cloud Credential in Use | HIGH | T1552.004 |
| FS005 | Pull Request Target — Secrets Exposed to Fork Code | CRITICAL | T1611 |
| FS006 | Missing Timeout — Job Runs Up to 6 Hours Unchecked | LOW | T1499 |
| FS007 | Self-Hosted Runner — Persistent Environment Risk | HIGH | T1053 |
| FS008 | Missing Artifact Signing — No Tamper Protection | MEDIUM | T1553 |

---

## Real findings on a real repo

Scanned `VanshBhardwaj1945/cloud-resume-challenge-azure` — 13 findings across 2 workflow files:

```
[CRITICAL] FS002 - Unpinned Action — Supply Chain Attack Vector
  File: .github/workflows/backend.main.yaml
  Action 'actions/checkout@v4' is not pinned to a commit hash

[CRITICAL] FS002 - Unpinned Action — Supply Chain Attack Vector
  File: .github/workflows/backend.main.yaml
  Action 'azure/login@v2' is not pinned to a commit hash

[HIGH]     FS003 - Excessive Permissions — Overprivileged Workflow Token
  File: .github/workflows/backend.main.yaml
  Pipeline permissions set to 'None' — GitHub defaults apply

[HIGH]     FS004 - Missing OIDC — Long-Lived Cloud Credential in Use
  File: .github/workflows/backend.main.yaml
  Cloud provider action present but no id-token: write permission

[LOW]      FS006 - Missing Timeout — Job Runs Up to 6 Hours Unchecked
  File: .github/workflows/backend.main.yaml
  Job 'build-and-deploy' has no timeout — GitHub default is 6 hours
```

---

## Stack

| Layer | Tools |
|---|---|
| Language | Python 3.11 |
| GitHub Connection | PyGithub |
| YAML Parsing | PyYAML with custom line-tracking loader |
| Terminal Output | rich |
| HTML Reports | Jinja2 — interactive filtering, expandable findings, PDF export |
| AI Narratives | Anthropic Claude API with local caching |
| Testing | pytest, pytest-mock, pytest-cov |
| Linting | ruff, mypy, bandit |
| Packaging | hatch, pyproject.toml |
| Containerization | Docker |

---

## Quick Start

```bash
git clone https://github.com/VanshBhardwaj1945/FlowSec.git
cd FlowSec
python3 -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
cp .env.example .env
# Add your GITHUB_TOKEN to .env
flowsec scan --repo owner/repo
flowsec scan --file path/to/workflow.yml
flowsec scan --repo owner/repo --output report.html
flowsec scan --repo owner/repo --ai
```

---

## Use as a Pipeline Gate

Add FlowSec to your own GitHub Actions workflow to automatically block PRs that introduce security misconfigurations:

```yaml
name: FlowSec Security Scan
on: [push, pull_request]
jobs:
  security:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - name: Install FlowSec
        run: pip install flowsec
      - name: Run FlowSec
        run: flowsec scan --file .github/workflows/ --fail-on-critical
```

`--fail-on-critical` exits with a non-zero code if any CRITICAL findings are found, failing the pipeline and blocking the PR.

---

## Status

| Component | Status |
|---|---|
| Rule engine abstract base class | Complete |
| YAML parser with line number tracking | Complete |
| All 8 security rules FS001-FS008 | Complete |
| GitHub API scanner | Complete |
| Local file scanner | Complete |
| CLI — scan --repo and --file | Complete |
| Rich terminal output with risk score | Complete |
| HTML report with interactive filtering and PDF export | Complete |
| AI attack narratives with local caching | Complete |
| Line number tracking | Complete |
| --fail-on-critical pipeline gate flag | In Progress |
| FS009-FS013 new rules — OWASP + SLSA + CIS | In Progress |
| GitLab CI support | In Progress |
| Azure DevOps support | In Progress |
| Tests | In Progress |
| PyPI publish | Pending |
| Web app — FastAPI + frontend | Pending |
| Web app — Azure Container Apps deployment | Pending |

---

## Roadmap

**Phase 1 — Core CLI**
Pipeline gate flag, 5 new rules mapped to OWASP CICD Top 10 and SLSA, GitLab CI and Azure DevOps support, full test suite, PyPI publish.

**Phase 2 — Web App**
FastAPI backend, frontend for repo input and file upload, deployed to Azure Container Apps via GitHub Actions. Anyone can scan a pipeline from a browser without installing anything.

**Phase 3 — Expansion**
Jenkins support, AWS CodePipeline, 20+ rule library, rate limiting.

---

## About this project

Built as a security engineering portfolio project. The goal was to build an actual security tool — not run existing ones — and document every decision along the way.

**[Read the full documentation](docs/FULL_README.md)**