# FlowSec

> A Python security tool that connects to GitHub, pulls CI/CD pipeline configs, and runs a library of security rules against them to find attack vectors. Every finding maps to a MITRE ATT&CK technique.
>
> The pipeline is the attack surface. FlowSec treats it that way.

**[Full documentation](docs/FULL_README.md)**

---


## What it catches

Hardcoded Secrets → Unpinned Actions → Excessive Permissions → Missing OIDC → Pull Request Target Misuse → Missing Timeouts → Self Hosted Runner Isolation → Artifact Signing

| ID | Rule | Severity | MITRE |
|---|---|---|---|
| FS001 | Hardcoded Secrets | CRITICAL | T1552.001 |
| FS002 | Unpinned Actions | CRITICAL | T1195.001 |
| FS003 | Excessive Permissions | HIGH | T1078 |
| FS004 | Missing OIDC | MEDIUM | T1552 |
| FS005 | Pull Request Target Misuse | CRITICAL | T1611 |
| FS006 | Missing Job Timeout | LOW | T1499 |
| FS007 | Self Hosted Runner Isolation | HIGH | T1053 |
| FS008 | Missing Artifact Signing | MEDIUM | T1553 |

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

Active development — Week 1 of 4.

| Component | Status |
|---|---|
| Project structure and packaging | Complete |
| Rule engine abstract base class | Complete |
| YAML parser | Complete |
| FS001 Hardcoded Secrets | Complete |
| FS002 Unpinned Actions | Complete |
| FS003 — FS008 remaining rules | In progress |
| GitHub API scanner | Pending |
| CLI interface | Pending |
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