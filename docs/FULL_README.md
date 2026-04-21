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
| anthropic | Claude API — generates AI attack narratives per finding |
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
│       ├── parser.py            — YAML to Python dict conversion with line tracking
│       ├── scoring.py           — risk score aggregation
│       ├── report.py            — HTML report generation via Jinja2
│       ├── ai_narrative.py      — Claude API integration with local caching
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
Each workflow file comes back from the API as raw text. A custom PyYAML loader converts it into a Python dictionary while preserving line number information for each key. This is what allows findings to report exactly which line in the file the problem is on.

**Layer 3 — Scan**
The rule engine loops through every rule in the `RULES` list and runs `check()` against each parsed config. All findings from all rules across all files get collected into one flat list.

**Layer 4 — Score**
Findings are aggregated into a weighted risk score — CRITICAL×10, HIGH×5, MEDIUM×3, LOW×1.

**Layer 5 — Output**
Three outputs. The terminal gets a Rich colored table with severity badges and a summary panel. An HTML report with interactive filtering, expandable findings, AI narratives, and PDF export can be generated with `--output`. AI attack narratives are generated per finding via the Claude API with `--ai`, cached locally so the same finding is never called twice.

---

## Rule Engine

Three components in `src/pipelineguard/rules/base.py` form the foundation everything else builds on.

**Severity**
An enum with four levels — CRITICAL, HIGH, MEDIUM, LOW. Using an enum instead of plain strings means a typo throws an immediate error rather than silently producing a broken report.

**Finding**
A dataclass that every rule returns when it detects a problem. Every finding has the same shape regardless of which rule produced it — rule ID, title, severity, description, remediation, MITRE technique, file path, line number, and AI narrative.

**BaseRule**
An abstract base class every rule inherits from. It enforces that every rule must implement a `check()` method. If a new rule is written without `check()`, Python throws an error at import time. `check()` takes the parsed config dictionary and the file path, and returns a list of `Finding` objects.

Adding a new rule means one new file, inheriting from `BaseRule`, implementing `check()`, and adding it to the `RULES` list in `scanner.py`. Nothing else changes.

---

## Rules

**FS001 — Hardcoded Secret — Plaintext Credential in Workflow**
MITRE T1552.001 — Credentials in Files

Scans every environment variable across every job and step. If the variable name matches a suspicious pattern — API_KEY, PASSWORD, TOKEN, SECRET, PRIVATE_KEY — and the value does not start with `${{`, it is flagged. `${{` means the value is pulling from GitHub Secrets at runtime and is safe. Line number tracking is implemented for this rule — findings report the exact line in the workflow file where the credential is defined.

**FS002 — Unpinned Action — Supply Chain Attack Vector**
MITRE T1195.001 — Supply Chain Compromise

Scans every `uses` field across all jobs and steps. An action is safely pinned only if it references a full 40 character git commit hash. Branch references like `@main` and version tags like `@v3` are both flagged. If an attacker compromises the action repo and pushes malicious code, any pipeline using `@main` automatically pulls and executes it on the next run. This is the same attack pattern as SolarWinds.

**FS003 — Excessive Permissions — Overprivileged Workflow Token**
MITRE T1078 — Valid Accounts

Checks the top-level permissions block. Flags `write-all`, `read-all`, and missing permissions blocks where GitHub's overly permissive defaults apply. A pipeline token with write-all can push code, modify releases, and exfiltrate secrets if an attacker gains access to the pipeline.

**FS004 — Missing OIDC — Long-Lived Cloud Credential in Use**
MITRE T1552.004 — Private Keys in Automated Pipelines

Detects pipelines that connect to cloud providers — AWS, Azure, GCP — without using OIDC. If a cloud provider action is present but `id-token: write` is missing from the permissions block, the pipeline is almost certainly using long-lived credentials. OIDC tokens expire when the job finishes — usually 15 minutes. Nothing to steal, nothing to rotate.

**FS005 — Pull Request Target — Secrets Exposed to Fork Code**
MITRE T1611 — Escape to Host

`pull_request_target` runs in the context of the base branch with full access to secrets — even when triggered by a fork. Combined with `actions/checkout`, an attacker submits a malicious PR that executes arbitrary code in your trusted environment with your secrets available.

**FS006 — Missing Timeout — Job Runs Up to 6 Hours Unchecked**
MITRE T1499 — Endpoint Denial of Service

Flags every job without a `timeout-minutes` field. GitHub's default timeout is 6 hours. A stuck job or deliberate attack burns through runner minutes, blocks other workflows, and racks up costs.

**FS007 — Self-Hosted Runner — Persistent Environment Risk**
MITRE T1053 — Scheduled Task and Job Abuse

Flags jobs using `self-hosted` in `runs-on`. Self-hosted runners persist between jobs unlike GitHub-hosted runners which are destroyed after each run. A malicious workflow can leave backdoors or stolen credentials on the runner that affect every subsequent job.

**FS008 — Missing Artifact Signing — No Tamper Protection**
MITRE T1553 — Subvert Trust Controls

Flags pipelines that publish artifacts — Docker images, PyPI packages, GitHub releases — without cryptographic signing. Without signed artifacts, consumers have no way to verify the artifact came from your pipeline and has not been tampered with.

---

## CLI

```bash
# Scan a GitHub repo
flowsec scan --repo VanshBhardwaj1945/cloud-resume-challenge-azure

# Scan a local workflow file
flowsec scan --file .github/workflows/ci.yml

# Generate an HTML report
flowsec scan --repo owner/repo --output report.html

# Generate AI attack narratives per finding
flowsec scan --repo owner/repo --ai

# Everything at once
flowsec scan --repo owner/repo --ai --output report.html
```

---

## AI Attack Narratives

When `--ai` is passed, FlowSec calls the Claude API for each finding and generates a structured attack narrative:

```
Attack Vector: [how the attacker exploits the misconfiguration]
What They Gain: [what access or capability they obtain]
Blast Radius: [realistic worst case impact]
```

Narratives are cached locally in `~/.flowsec_cache.json` using an MD5 hash of the finding's rule ID and description as the key. The same finding is never sent to the API twice — subsequent scans return the cached narrative instantly. This keeps costs negligible and scans fast.

---

## HTML Report

Generated with `--output report.html`. A self-contained single file — no internet connection needed to open it.

Features:
- Summary cards showing finding counts per severity and overall risk score
- Findings overview table with severity color coding
- Detailed expandable finding cards showing description, remediation, and AI narrative
- Filter by severity — click any card or filter button to show only that severity
- PDF export button that opens the browser print dialog with print-optimized CSS

---

## Scanner

`src/pipelineguard/scanner.py` connects everything together. It fetches workflow files from GitHub, parses each one using the line-tracking loader, and runs all rules against them. The `RULES` list at the top of the file is the only thing that changes when a new rule is added.

For local files, `scan_file()` reads from disk and runs the same rule engine without needing a GitHub token.

---

## Parser

`src/pipelineguard/parser.py` uses a custom PyYAML loader called `LineLoader` that subclasses `SafeLoader`. For every key/value pair it encounters, it stores the line number alongside the value using a hidden `__line_KEYNAME__` key. Rules can look up `env.get("__line_API_KEY__")` to get the exact line number of a finding. `safe_load` behavior is preserved — no code execution during parsing.

---

## Real Findings — cloud-resume-challenge-azure

FlowSec scanned a real production project and found 13 findings across two workflow files.

```
[CRITICAL] FS002 - Unpinned Action — Supply Chain Attack Vector
  File: .github/workflows/backend.main.yaml
  Action 'actions/checkout@v4' is not pinned to a commit hash

[CRITICAL] FS002 - Unpinned Action — Supply Chain Attack Vector
  File: .github/workflows/frontend.main.yaml
  Action 'azure/login@v2' is not pinned to a commit hash

[HIGH]     FS003 - Excessive Permissions — Overprivileged Workflow Token
  File: .github/workflows/backend.main.yaml
  Pipeline permissions are set to 'None' — GitHub defaults apply

[HIGH]     FS004 - Missing OIDC — Long-Lived Cloud Credential in Use
  File: .github/workflows/backend.main.yaml
  Cloud provider action present but no id-token: write permission

[LOW]      FS006 - Missing Timeout — Job Runs Up to 6 Hours Unchecked
  File: .github/workflows/backend.main.yaml
  Job 'build-and-deploy' has no timeout — GitHub default is 6 hours
```

---

## Roadmap

**Phase 1 — Core CLI**
`--fail-on-critical` pipeline gate flag, 5 new rules (FS009-FS013) mapped to OWASP CICD Top 10 and SLSA, GitLab CI support, Azure DevOps support, full test suite, PyPI publish.

**Phase 2 — Web App**
FastAPI backend wrapping the scanner, frontend for repo input and file upload, deployed to Azure Container Apps via GitHub Actions CI/CD. Anyone can scan a pipeline from a browser without installing anything.

**Phase 3 — Expansion**
Jenkins support, AWS CodePipeline support, 20+ rule library, rate limiting on web app.

---

## Using FlowSec as a Pipeline Gate

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

With `--fail-on-critical`, the workflow exits with a non-zero code if any CRITICAL findings are found, failing the pipeline and blocking the PR.

---

## Issues Resolved

| Issue | Resolution |
|---|---|
| PyYAML converts `on` to Python `True` | Known PyYAML behavior — does not affect rule accuracy |
| pip install blocked by macOS system Python | Created virtual environment with `python3 -m venv .venv` |
| venv created at wrong path | Ran example command literally — deleted and recreated at `.venv` |
| Click Arena has no `.github/workflows/` folder | Project uses Jenkins — tested against `cloud-resume-challenge-azure` instead |
| 404 on first scanner test | Pointed at wrong repo — switched to one that uses GitHub Actions |
| Python 3.14 editable install not creating `.pth` file | Known hatchling compatibility issue — fixed by setting `PYTHONPATH` permanently in `.zshrc` |
| GitHub push protection blocked commit | Real token in `.env.example` — revoked, regenerated, file restored to placeholders |
| `__line_` hidden keys picked up by hardcoded secrets rule | Added `startswith("__line_")` filter in `_extract_env_vars` |
| Line numbers returning 0 | `_extract_env_vars` stripped hidden keys before `check()` could use them — rewrote `check()` to access env dicts directly |