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

Scanned `VanshBhardwaj1945/cloud-resume-challenge-azure`:

```
[CRITICAL] FS002 - Unpinned Actions
  File: .github/workflows/backend.main.yaml

[CRITICAL] FS002 - Unpinned Actions
  File: .github/workflows/frontend.main.yaml

[HIGH] FS003 - Excessive Permissions
  File: .github/workflows/backend.main.yaml

[HIGH] FS004 - Missing OIDC
  File: .github/workflows/backend.main.yaml

[LOW] FS006 - Missing Job Timeout
  File: .github/workflows/backend.main.yaml
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
| CLI interface | In Progress |
| Rich terminal output | Pending |
| HTML report generation | Pending |
| AI attack narratives | Pending |
| Docker packaging | Pending |
| PyPI publish | Pending |

---

## Quick Start

Coming once the CLI is complete.

---

## About this project

Built as a portfolio project for security engineering and DevSecOps roles. The goal was to build an actual security tool — not run existing ones — and document every decision along the way.

**[Read the full documentation](docs/FULL_README.md)**