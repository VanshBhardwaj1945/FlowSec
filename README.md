# FlowSec

> A Python security tool that scans CI/CD pipeline configurations for attack vectors across GitHub Actions, GitLab CI, and Azure DevOps. Every finding maps to a MITRE ATT&CK technique and OWASP CICD Top 10 category.
>
> The pipeline is the attack surface. FlowSec treats it that way.

**[Full documentation](docs/FULL_README.md)**

---

[![Open in GitHub Codespaces](https://github.com/codespaces/badge.svg)](https://codespaces.new/VanshBhardwaj1945/FlowSec)

---

## What it catches

| ID | Rule | Severity | MITRE | OWASP |
|---|---|---|---|---|
| FS001 | Hardcoded Secret — Plaintext Credential in Workflow | CRITICAL | T1552.001 | CICD-SEC-6 |
| FS002 | Unpinned Action — Supply Chain Attack Vector | CRITICAL | T1195.001 | CICD-SEC-3 |
| FS003 | Excessive Permissions — Overprivileged Workflow Token | HIGH | T1078 | CICD-SEC-5 |
| FS004 | Missing OIDC — Long-Lived Cloud Credential in Use | HIGH | T1552.004 | CICD-SEC-6 |
| FS005 | Pull Request Target — Secrets Exposed to Fork Code | CRITICAL | T1611 | CICD-SEC-4 |
| FS006 | Missing Timeout — Job Runs Up to 6 Hours Unchecked | LOW | T1499 | CICD-SEC-10 |
| FS007 | Self-Hosted Runner — Persistent Environment Risk | HIGH | T1053 | CICD-SEC-7 |
| FS008 | Missing Artifact Signing — No Tamper Protection | MEDIUM | T1553 | CICD-SEC-8 |
| FS009 | Unpinned Dependency — Package Installed Without Version Lock | HIGH | T1195.002 | CICD-SEC-3 |
| FS010 | Secret in Run Command — Plaintext Credential in Shell Step | CRITICAL | T1552.001 | CICD-SEC-6 |
| FS011 | Missing Branch Protection — Direct Push to Default Branch Possible | HIGH | T1098 | CICD-SEC-1 |
| FS012 | Missing Environment Protection — Deploy Job Has No Approval Gate | HIGH | T1078 | CICD-SEC-5 |
| FS013 | Workflow Dispatch Injection — Unvalidated Input in Shell Command | CRITICAL | T1059 | CICD-SEC-9 |

---

## Platforms supported

| Platform | How to scan |
|---|---|
| GitHub Actions | `flowsec scan --repo owner/repo` or `--file workflow.yml` |
| GitLab CI | `flowsec scan --gitlab .gitlab-ci.yml` |
| Azure DevOps | `flowsec scan --azure azure-pipelines.yml` |

---

## Real findings on a real repo

Scanned `VanshBhardwaj1945/cloud-resume-challenge-azure` — 13 findings across 2 workflow files:

```
[CRITICAL] FS002 - Unpinned Action — Supply Chain Attack Vector
  File: .github/workflows/backend.main.yaml
  Action 'actions/checkout@v4' is not pinned to a commit hash

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
| Linting | ruff, mypy, bandit |
| Packaging | hatch, pyproject.toml |
| Containerization | Docker |

---

## Quick Start

Click the Codespaces button above to run FlowSec in your browser with zero setup. Or run locally:

```bash
git clone https://github.com/VanshBhardwaj1945/FlowSec.git
cd FlowSec
python3 -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
cp .env.example .env
# Add your GITHUB_TOKEN to .env

flowsec scan --repo owner/repo
flowsec scan --file .github/workflows/ci.yml
flowsec scan --gitlab .gitlab-ci.yml
flowsec scan --azure azure-pipelines.yml
flowsec scan --repo owner/repo --ai --output report.html
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
        run: flowsec scan --file .github/workflows/ --fail-on critical
```

`--fail-on critical` exits with code 1 if any CRITICAL findings are found, failing the pipeline and blocking the PR. Supports `critical`, `high`, `medium`, and `low` thresholds.

---

## Status

| Component | Status |
|---|---|
| Rule engine — BaseRule, Finding, Severity | Complete |
| YAML parser with line number tracking | Complete |
| 13 security rules FS001-FS013 | Complete |
| MITRE ATT&CK + OWASP CICD Top 10 mapping | Complete |
| Platform-aware rule engine | Complete |
| GitHub Actions scanner — API and local file | Complete |
| GitLab CI scanner | Complete |
| Azure DevOps scanner | Complete |
| CLI — --repo, --file, --gitlab, --azure, --ai, --output, --fail-on | Complete |
| Rich terminal output with risk score | Complete |
| HTML report with filtering, PDF export | Complete |
| AI attack narratives with local caching | Complete |
| Line number tracking | Complete |
| Pipeline gate flag --fail-on | Complete |
| GitHub Codespace config | Complete |
| PyPI publish | Pending |
| Web app — FastAPI + frontend | Pending |
| Web app — Azure Container Apps deployment | Pending |

---

## Roadmap

**Phase 1 — Core CLI**
PyPI publish so anyone can `pip install flowsec`.

**Phase 2 — Web App**
FastAPI backend, frontend for repo input and file upload, deployed to Azure Container Apps via GitHub Actions. Anyone can scan a pipeline from a browser without installing anything.

**Phase 3 — Expansion**
Jenkins support, AWS CodePipeline, 20+ rule library, rate limiting.

---

## About this project

Built as a security engineering portfolio project. The goal was to build an actual security tool — not run existing ones — and document every decision along the way.

**[Read the full documentation](docs/FULL_README.md)**