# FlowSec

> A Python security tool that connects to GitHub, pulls CI/CD pipeline configs, and runs a library of security rules against them to find attack vectors. Every finding maps to a MITRE ATT&CK technique.
>
> The pipeline is the attack surface. FlowSec treats it that way.

**[Full documentation](docs/FULL_README.md)**

---

## What it catches

| ID | Rule | Severity | MITRE |
|---|---|---|---|
| FS001 | Hardcoded Secrets | CRITICAL | T1552.001 |
| FS002 | Unpinned Actions | CRITICAL | T1195.001 |
| FS003 | Excessive Permissions | HIGH | T1078 |
| FS004 | Missing OIDC | HIGH | T1552.004 |
| FS005 | Pull Request Target Misuse | CRITICAL | T1611 |
| FS006 | Missing Job Timeout | LOW | T1499 |
| FS007 | Self Hosted Runner Isolation | HIGH | T1053 |
| FS008 | Missing Artifact Signing | MEDIUM | T1553 |

---

## Real findings on a real repo

Scanned `VanshBhardwaj1945/cloud-resume-challenge-azure` — 13 findings across 2 workflow files:

```
[CRITICAL] FS002 - Unpinned Actions
  File: .github/workflows/backend.main.yaml
  Action 'actions/checkout@v4' is not pinned to a commit hash

[CRITICAL] FS002 - Unpinned Actions
  File: .github/workflows/backend.main.yaml
  Action 'azure/login@v2' is not pinned to a commit hash

[HIGH]     FS003 - Excessive Permissions
  File: .github/workflows/backend.main.yaml
  Pipeline permissions are set to 'None' — GitHub defaults apply

[HIGH]     FS004 - Missing OIDC
  File: .github/workflows/backend.main.yaml
  Cloud provider action present but no id-token: write permission

[LOW]      FS006 - Missing Job Timeout
  File: .github/workflows/backend.main.yaml
  Job 'build-and-deploy' has no timeout — GitHub default is 6 hours
```

---

## Stack

| Layer | Tools |
|---|---|
| Language | Python 3.11 |
| GitHub Connection | PyGithub |
| YAML Parsing | PyYAML |
| Terminal Output | rich |
| HTML Reports | Jinja2 |
| AI Narratives | Anthropic Claude API |
| Testing | pytest, pytest-mock, pytest-cov |
| Linting | ruff, mypy, bandit |
| Packaging | hatch, pyproject.toml |
| Containerization | Docker |

---

## Status

| Component | Status |
|---|---|
| Project structure and packaging | Complete |
| Rule engine abstract base class | Complete |
| YAML parser | Complete |
| All 8 security rules | Complete |
| GitHub API scanner | Complete |
| CLI interface | Complete |
| Rich terminal output | Complete |
| HTML report generation | In Progress |
| AI attack narratives | In Progress |
| Line number tracking | In Progress |
| Tests | In Progress |
| Demo GIF | Pending |
| GitHub Codespace config | Pending |
| Web app — FastAPI + frontend | Pending |
| Web app — Docker + GitHub Actions CI/CD | Pending |
| Web app — Azure Container Apps deployment | Pending |
| PyPI publish | Pending |

---

## Roadmap

**Phase 1 — Core CLI tool**
Finish HTML report, AI attack narratives, line number tracking, tests, and demo GIF. This is the installable Python tool published to PyPI.

**Phase 2 — Web app**
FastAPI backend wrapping the scanner, simple frontend for repo input and file upload, deployed to Azure Container Apps via GitHub Actions. Anyone can scan a pipeline from a browser without installing anything.

**Phase 3 — Rule expansion**
The rule engine is designed to be pluggable. Adding a new rule is one new file with zero changes to the core scanner. More rules covering additional attack vectors will be added continuously.

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
```

---

## About this project

Built as a portfolio project for security engineering and DevSecOps roles. The goal was to build an actual security tool — not run existing ones — and document every decision along the way.

**[Read the full documentation](docs/FULL_README.md)**
