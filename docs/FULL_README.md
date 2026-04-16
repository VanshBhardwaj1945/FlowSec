# FlowSec — Full Documentation

## What is this project?

FlowSec is a Python command line security tool that scans CI/CD pipeline configurations for attack vectors. It connects to the GitHub API, pulls every workflow YAML file from a target repository, runs a library of security rules against them, and outputs a prioritized list of findings with a risk score.

Every finding maps to a MITRE ATT&CK technique. Every rule has a documented attack narrative explaining exactly how the misconfiguration gets exploited in the real world.

The rule engine is pluggable — adding a new rule is one new file. Nothing else in the codebase changes.

---

## Why pipelines are an attack surface

A CI/CD pipeline runs code automatically on every push with access to production secrets, cloud credentials, and deployment infrastructure. Most organizations spend significant time securing their application code and almost no time auditing the pipeline configs that deploy it.

A single misconfiguration — a hardcoded token, an unpinned action, an overpermissioned job — can give an attacker a direct path into production. FlowSec finds those misconfigurations before an attacker does.

---

## Stack

| Tool | Purpose |
|---|---|
| Python 3.11 | Core language |
| PyGithub | GitHub API — fetches workflow files from target repos |
| PyYAML | Parses YAML pipeline configs into Python dictionaries |
| rich | Colored terminal output — findings tables, risk score summary |
| anthropic | Claude API — generates attack narratives per finding |
| jinja2 | HTML report templating |
| Pygments | Syntax highlighting in HTML report |
| python-dotenv | Loads API credentials from .env locally |
| pytest | Test suite |
| pytest-mock | Mocks GitHub API responses in tests |
| pytest-cov | Coverage reporting |
| ruff | Linting and formatting |
| mypy | Type checking — all functions typed from day one |
| bandit | Scans FlowSec's own Python code for security issues |
| hatch | Build and PyPI publishing |
| Docker | Multi-stage container packaging |

---

## Project Structure

```
FlowSec/
├── src/
│   └── pipelineguard/
│       ├── cli.py               — argparse CLI, Rich terminal output
│       ├── scanner.py           — GitHub API connection and rule orchestration
│       ├── parser.py            — YAML to Python dict conversion
│       ├── scoring.py           — risk score aggregation
│       ├── report.py            — HTML report generation via Jinja2
│       ├── ai_narrative.py      — Claude API integration
│       └── rules/
│           ├── base.py          — BaseRule ABC, Finding dataclass, Severity enum
│           ├── hardcoded_secrets.py
│           ├── unpinned_actions.py
│           ├── excessive_permissions.py
│           ├── missing_oidc.py
│           ├── pull_request_target.py
│           ├── missing_timeout.py
│           ├── self_hosted_runner.py
│           └── artifact_signing.py
├── tests/
│   ├── fixtures/
│   │   ├── sample_workflow_clean.yml
│   │   └── sample_workflow_vulnerable.yml
│   └── test_*.py
├── docs/
├── pyproject.toml
├── Makefile
├── Dockerfile
└── docker-compose.yml
```

---

## Architecture

Five layers. Each has one job and passes its output to the next.

**Layer 1 — Connect**
The scanner connects to GitHub using PyGithub and a personal access token loaded from a local `.env` file. It fetches every `.yml` and `.yaml` file inside `.github/workflows/` of the target repo.

**Layer 2 — Parse**
Each workflow file comes back from the API as raw text. PyYAML converts it into a Python dictionary. The rules work with this dictionary — not raw text. `yaml.safe_load` is used instead of `yaml.load` because `safe_load` refuses to execute any code that might be embedded in the YAML, preventing code execution during parsing.

**Layer 3 — Scan**
The rule engine loops through every rule in the `RULES` list and runs `check()` against each parsed config. All findings from all rules across all files get collected into one flat list.

**Layer 4 — Score**
Findings are aggregated into a risk score. CRITICAL findings carry more weight than LOW findings — weighted as CRITICAL×10, HIGH×5, MEDIUM×3, LOW×1.

**Layer 5 — Output**
Two outputs. The terminal gets a Rich colored table sorted by severity with a summary panel showing finding counts and risk score. An HTML file can be generated using Jinja2 with the full finding details.

---

## Rule Engine

Three components in `src/pipelineguard/rules/base.py` form the foundation everything else builds on.

**Severity**
An enum with four levels — CRITICAL, HIGH, MEDIUM, LOW. Using an enum instead of plain strings means a typo throws an immediate error rather than silently producing a broken report.

**Finding**
A dataclass that every rule returns when it detects a problem. Every finding has the same shape regardless of which rule produced it — rule ID, title, severity, description, remediation, MITRE technique, file path, and line number. The report generator always knows exactly what fields to expect.

**BaseRule**
An abstract base class every rule inherits from. It enforces that every rule must implement a `check()` method. If a new rule is written without `check()`, Python throws an error at import time. `check()` takes the parsed config dictionary and the file path, and returns a list of `Finding` objects — a list because a single file can have multiple instances of the same problem.

Adding a new rule means one new file, inheriting from `BaseRule`, implementing `check()`, and adding it to the `RULES` list in `scanner.py`. Nothing else changes.

---

## Rules

**FS001 — Hardcoded Secrets**
MITRE T1552.001 — Credentials in Files

Scans every environment variable across every job and step. If the variable name matches a suspicious pattern — API_KEY, PASSWORD, TOKEN, SECRET, PRIVATE_KEY — and the value does not start with `${{`, it is flagged. `${{` means the value is pulling from GitHub Secrets at runtime and is safe. Anything else is a plaintext credential sitting in a file committed to git.

**FS002 — Unpinned Actions**
MITRE T1195.001 — Supply Chain Compromise

Scans every `uses` field across all jobs and steps. An action is safely pinned only if it references a full 40 character git commit hash. Branch references like `@main` and version tags like `@v3` are both flagged. If an attacker compromises the action repo and pushes malicious code, any pipeline using `@main` automatically pulls and executes it on the next run. This is the same attack pattern as SolarWinds — malicious code injected into a trusted dependency.

**FS003 — Excessive Permissions**
MITRE T1078 — Valid Accounts

Checks the top-level permissions block. Flags `write-all`, `read-all`, and missing permissions blocks where GitHub's overly permissive defaults apply. A pipeline token with write-all can push code, modify releases, and exfiltrate secrets if an attacker gains access to the pipeline.

**FS004 — Missing OIDC**
MITRE T1552.004 — Private Keys in Automated Pipelines

Detects pipelines that connect to cloud providers — AWS, Azure, GCP — without using OIDC. If a cloud provider action is present but `id-token: write` is missing from the permissions block, the pipeline is almost certainly using long-lived credentials. Long-lived credentials exist until someone manually rotates them. OIDC tokens expire when the job finishes — usually 15 minutes. Nothing to steal, nothing to rotate.

**FS005 — Pull Request Target Misuse**
MITRE T1611 — Escape to Host

`pull_request_target` runs in the context of the base branch with full access to secrets — even when triggered by a fork. Combined with `actions/checkout`, an attacker submits a malicious PR that executes arbitrary code in your trusted environment with your secrets available. Several major open source projects were compromised through this exact misconfiguration.

**FS006 — Missing Job Timeout**
MITRE T1499 — Endpoint Denial of Service

Flags every job without a `timeout-minutes` field. GitHub's default timeout is 6 hours. A stuck job or deliberate attack burns through runner minutes, blocks other workflows, and racks up costs.

**FS007 — Self Hosted Runner Isolation**
MITRE T1053 — Scheduled Task and Job Abuse

Flags jobs using `self-hosted` in `runs-on`. Self-hosted runners persist between jobs unlike GitHub-hosted runners which are destroyed after each run. A malicious workflow can leave backdoors or stolen credentials on the runner that affect every subsequent job.

**FS008 — Missing Artifact Signing**
MITRE T1553 — Subvert Trust Controls

Flags pipelines that publish artifacts — Docker images, PyPI packages, GitHub releases — without cryptographic signing. Without signed artifacts, consumers have no way to verify the artifact came from your pipeline and has not been tampered with in transit or storage.

---

## CLI

FlowSec is installed as a command line tool. Two scan modes:

```bash
# Scan a GitHub repo
flowsec scan --repo VanshBhardwaj1945/cloud-resume-challenge-azure

# Scan a local workflow file
flowsec scan --file .github/workflows/ci.yml

# Generate an HTML report
flowsec scan --repo owner/repo --output report.html
```

Terminal output uses Rich to render a colored findings table with severity badges and a summary panel showing total findings, counts per severity level, and a weighted risk score.

---

## Real Findings — cloud-resume-challenge-azure

FlowSec scanned a real production project and found 13 findings across two workflow files.

```
[CRITICAL] FS002 - Unpinned Actions
  File: .github/workflows/backend.main.yaml
  Action 'actions/checkout@v4' is not pinned to a commit hash

[CRITICAL] FS002 - Unpinned Actions
  File: .github/workflows/frontend.main.yaml
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

The tool works against real code, not just constructed examples.

---

## Roadmap

**Phase 1 — Core CLI tool**
HTML report generation, AI attack narratives via Claude API, line number tracking, tests, and demo GIF. Published to PyPI.

**Phase 2 — Web app**
FastAPI backend wrapping the scanner, frontend for repo input and file upload, deployed to Azure Container Apps via GitHub Actions CI/CD. Anyone can scan a pipeline from a browser without installing anything.

**Phase 3 — Rule expansion**
The rule engine supports unlimited rules with zero changes to the core scanner. Additional rules covering more attack vectors will be added continuously.

---

## Issues Resolved

| Issue | Resolution |
|---|---|
| PyYAML converts `on` to Python `True` | Known PyYAML behavior — does not affect rule accuracy since no rules inspect the trigger block |
| pip install blocked by macOS system Python | Created virtual environment with `python3 -m venv .venv` |
| venv created at wrong path | Ran example command literally — deleted and recreated at `.venv` |
| Click Arena has no `.github/workflows/` folder | Project uses Jenkins — tested against `cloud-resume-challenge-azure` instead |
| 404 on first scanner test | Pointed at wrong repo — switched to one that uses GitHub Actions |
| Python 3.14 editable install not creating `.pth` file | Known hatchling compatibility issue with Python 3.14 — fixed by setting `PYTHONPATH` permanently in `.zshrc` |
| GitHub push protection blocked commit | Real token accidentally added to `.env.example` — token revoked, regenerated, and `.env.example` restored to placeholders |
