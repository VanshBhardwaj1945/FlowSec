# FlowSec — Full Documentation

## What is this project?

FlowSec is a Python command line security tool that scans CI/CD pipeline configurations for attack vectors. It connects to the GitHub API, pulls every workflow YAML file from a target repository, runs a library of security rules against them, and outputs a prioritized list of findings with a risk score.

Every finding maps to both a MITRE ATT&CK technique and an OWASP CICD Top 10 category. Every rule has a documented attack narrative explaining exactly how the misconfiguration gets exploited in the real world.

The rule engine is pluggable and platform-aware — adding a new rule is one new file, and every rule supports GitHub Actions, GitLab CI, and Azure DevOps through a single `platform` parameter.

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
├── .devcontainer/
│   └── devcontainer.json    — GitHub Codespace config
├── src/
│   └── pipelineguard/
│       ├── cli.py               — argparse CLI, Rich terminal output
│       ├── scanner.py           — GitHub API connection and rule orchestration
│       ├── parser.py            — YAML to Python dict conversion with line tracking
│       ├── report.py            — HTML report generation via Jinja2
│       ├── ai_narrative.py      — Claude API integration with local caching
│       └── rules/
│           ├── base.py                      — BaseRule ABC, Finding dataclass, Severity enum
│           ├── hardcoded_secrets.py         — FS001
│           ├── unpinned_actions.py          — FS002
│           ├── excessive_permissions.py     — FS003
│           ├── missing_oidc.py              — FS004
│           ├── pull_request_target.py       — FS005
│           ├── missing_timeout.py           — FS006
│           ├── self_hosted_runner.py        — FS007
│           ├── artifact_signing.py          — FS008
│           ├── dependency_pinning.py        — FS009
│           ├── secrets_in_run.py            — FS010
│           ├── missing_branch_protection.py — FS011
│           ├── missing_env_protection.py    — FS012
│           └── workflow_dispatch_injection.py — FS013
├── tests/
│   ├── fixtures/
│   │   ├── sample_workflow_vulnerable.yml
│   │   ├── sample_workflow_clean.yml
│   │   ├── sample_gitlab_vulnerable.yml
│   │   └── sample_azure_vulnerable.yml
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
The scanner connects to the target platform using the appropriate client. For GitHub it uses PyGithub with a personal access token. For GitLab and Azure DevOps it reads local files directly. It fetches every pipeline config file from the target.

**Layer 2 — Parse**
Each pipeline file is converted into a Python dictionary using a custom PyYAML loader called `LineLoader`. This loader preserves line number information for every key — stored as hidden `__line_KEYNAME__` entries — so findings can report exactly which line the problem is on.

**Layer 3 — Scan**
The rule engine loops through every rule in the `RULES` list and calls `check(config, file_path, platform)`. The `platform` parameter tells each rule which part of the config to inspect. All findings from all rules across all files get collected into one flat list.

**Layer 4 — Score**
Findings are aggregated into a weighted risk score — CRITICAL×10, HIGH×5, MEDIUM×3, LOW×1.

**Layer 5 — Output**
Three output modes. The terminal gets a Rich colored table with MITRE and OWASP columns and a summary panel. An HTML report with interactive filtering, expandable cards, AI narratives, and PDF export is generated with `--output`. AI narratives per finding are generated via the Claude API with `--ai` and cached locally.

---

## Platform Support

FlowSec scans three CI/CD platforms. All 13 rules are platform-aware — each rule internally knows how to find the relevant config fields on each platform.

| Platform | Trigger | Pipeline File |
|---|---|---|
| GitHub Actions | `--repo` or `--file` | `.github/workflows/*.yml` |
| GitLab CI | `--gitlab` | `.gitlab-ci.yml` |
| Azure DevOps | `--azure` | `azure-pipelines.yml` |

Rules that are GitHub-specific — FS002 Unpinned Actions, FS003 Excessive Permissions, FS004 Missing OIDC, FS005 Pull Request Target, FS008 Artifact Signing — return no findings for GitLab and Azure since those misconfigurations don't apply to those platforms.

---

## Rule Engine

Three components in `src/pipelineguard/rules/base.py` form the foundation everything else builds on.

**Severity**
An enum with four levels — CRITICAL, HIGH, MEDIUM, LOW. Using an enum instead of plain strings means a typo throws an immediate error rather than silently producing a broken report.

**Finding**
A dataclass that every rule returns when it detects a problem. Every finding has the same shape regardless of which rule or platform produced it.

```python
@dataclass
class Finding:
    rule_id: str          # "FS001"
    title: str            # human readable name
    severity: Severity    # CRITICAL / HIGH / MEDIUM / LOW
    description: str      # what the problem is
    remediation: str      # how to fix it
    mitre_technique: str  # "T1552.001"
    owasp_category: str   # "CICD-SEC-6"
    file_path: str        # which pipeline file
    line_number: int = 0  # where in the file
    narrative: str = ""   # AI generated attack narrative
```

**BaseRule**
An abstract base class every rule inherits from. Every rule must implement `check(config, file_path, platform)`. If a new rule is written without it Python throws an error at import time.

Adding a new rule means one new file, inheriting from `BaseRule`, implementing `check()`, and adding it to the `RULES` list in `scanner.py`. Nothing else changes.

---

## Rules

**FS001 — Hardcoded Secret — Plaintext Credential in Workflow**
MITRE T1552.001 | OWASP CICD-SEC-6

Scans environment variables on GitHub (`jobs → env`), top-level `variables:` on GitLab, and `variables:` on Azure DevOps. Flags any variable matching suspicious name patterns — API_KEY, PASSWORD, TOKEN, SECRET — whose value doesn't reference a secret manager. Line number tracking is implemented for GitHub Actions findings.

**FS002 — Unpinned Action — Supply Chain Attack Vector**
MITRE T1195.001 | OWASP CICD-SEC-3 | GitHub only

Scans every `uses` field. Safe only if pinned to a full 40 character git commit hash. Branch references like `@main` and version tags like `@v3` are flagged. This is the GitHub Actions equivalent of the SolarWinds attack — malicious code injected into a trusted dependency that downstream pipelines pull automatically.

**FS003 — Excessive Permissions — Overprivileged Workflow Token**
MITRE T1078 | OWASP CICD-SEC-5 | GitHub only

Checks the top-level `permissions` block. Flags `write-all`, `read-all`, and missing permissions blocks where GitHub's permissive defaults apply.

**FS004 — Missing OIDC — Long-Lived Cloud Credential in Use**
MITRE T1552.004 | OWASP CICD-SEC-6 | GitHub only

Detects pipelines connecting to AWS, Azure, or GCP without OIDC. If a cloud provider action is present but `id-token: write` is missing, the pipeline is using long-lived credentials. OIDC tokens expire in 15 minutes. Nothing to steal, nothing to rotate.

**FS005 — Pull Request Target — Secrets Exposed to Fork Code**
MITRE T1611 | OWASP CICD-SEC-4 | GitHub only

`pull_request_target` combined with `actions/checkout` lets an attacker submit a malicious PR that executes arbitrary code with full access to repository secrets.

**FS006 — Missing Timeout — Job Runs Up to 6 Hours Unchecked**
MITRE T1499 | OWASP CICD-SEC-10 | All platforms

Flags jobs without timeout configuration. GitHub default is 6 hours (`timeout-minutes`), GitLab default is 1 hour (`timeout`), Azure DevOps uses `timeoutInMinutes`.

**FS007 — Self-Hosted Runner — Persistent Environment Risk**
MITRE T1053 | OWASP CICD-SEC-7 | All platforms

GitHub: flags `runs-on: self-hosted`. GitLab: flags `tags:` containing self-hosted. Azure: flags custom agent pool names. Self-hosted runners persist between jobs and can be poisoned by malicious workflows.

**FS008 — Missing Artifact Signing — No Tamper Protection**
MITRE T1553 | OWASP CICD-SEC-8 | GitHub only

Flags pipelines that publish Docker images, PyPI packages, or GitHub releases without cryptographic signing via Sigstore or SLSA.

**FS009 — Unpinned Dependency — Package Installed Without Version Lock**
MITRE T1195.002 | OWASP CICD-SEC-3 | All platforms

Scans `run:` commands on GitHub and `script:` on GitLab and Azure for `pip install`, `npm install`, and `yarn add` commands without version pins. Unpinned installs are vulnerable to dependency confusion and malicious package publication attacks.

**FS010 — Secret in Run Command — Plaintext Credential in Shell Step**
MITRE T1552.001 | OWASP CICD-SEC-6 | All platforms

Scans shell commands for credential patterns — `password=`, `token=`, `Authorization: Bearer` — followed by values that don't reference a secret manager. Credentials in shell commands appear in pipeline logs and git history.

**FS011 — Missing Branch Protection — Direct Push to Default Branch Possible**
MITRE T1098 | OWASP CICD-SEC-1 | Scaffold

Branch protection is a repository setting not a pipeline config. Full implementation requires GitHub API integration — scaffolded for the upcoming scanner refactor.

**FS012 — Missing Environment Protection — Deploy Job Has No Approval Gate**
MITRE T1078 | OWASP CICD-SEC-5 | GitHub only

Flags deployment jobs — identified by keywords like `deploy`, `release`, `prod` in the job name — that have no `environment:` key. Without GitHub Environments configured, deployments to production happen automatically with no human approval required.

**FS013 — Workflow Dispatch Injection — Unvalidated Input in Shell Command**
MITRE T1059 | OWASP CICD-SEC-9 | GitHub only

Flags `workflow_dispatch` workflows where `${{ inputs.* }}` appears unquoted in shell commands. An attacker with access to trigger the workflow can inject arbitrary shell commands through input fields.

---

## CLI

```bash
# GitHub Actions — remote repo
flowsec scan --repo VanshBhardwaj1945/cloud-resume-challenge-azure

# GitHub Actions — local file
flowsec scan --file .github/workflows/ci.yml

# GitLab CI — local file
flowsec scan --gitlab .gitlab-ci.yml

# Azure DevOps — local file
flowsec scan --azure azure-pipelines.yml

# Generate HTML report
flowsec scan --repo owner/repo --output report.html

# Generate AI attack narratives
flowsec scan --repo owner/repo --ai

# Pipeline gate — fail if critical findings exist
flowsec scan --repo owner/repo --fail-on critical

# Everything at once
flowsec scan --repo owner/repo --ai --output report.html --fail-on high
```

---

## Pipeline Gate

FlowSec can be used as a security gate in your own CI/CD pipeline. The `--fail-on` flag exits with code 1 if findings at or above the specified severity are found, failing the pipeline and blocking the PR.

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

Supported thresholds: `critical`, `high`, `medium`, `low`.

---

## AI Attack Narratives

When `--ai` is passed, FlowSec calls the Claude API for each finding and generates a structured attack narrative:

```
Attack Vector: [how the attacker exploits this specific misconfiguration]
What They Gain: [what access or capability they obtain]
Blast Radius: [realistic worst case impact on this organization]
```

Narratives are cached locally in `~/.flowsec_cache.json` using an MD5 hash of the finding's rule ID and description as the key. The same finding is never sent to the API twice — subsequent scans with the same findings return cached narratives instantly at zero cost.

---

## HTML Report

Generated with `--output report.html`. A self-contained single file — no internet connection needed to open it.

Features:
- Summary cards showing finding counts per severity and overall risk score — clickable to filter
- Findings overview table with MITRE and OWASP columns
- Detailed expandable finding cards showing description, remediation, and AI narrative
- OWASP category tags in green alongside MITRE tags in blue
- PDF export button with print-optimized CSS

---

## Parser

`src/pipelineguard/parser.py` uses a custom PyYAML loader called `LineLoader` that subclasses `SafeLoader`. For every key/value pair it encounters, it stores the line number alongside the value using a hidden `__line_KEYNAME__` key. Rules look up `env.get("__line_API_KEY__")` to get the exact line number of a finding.

Known quirk — PyYAML converts the YAML key `on` to the Python boolean `True`. This does not affect any rules since none of them inspect the trigger block directly.

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
PyPI publish — `pip install flowsec`.

**Phase 2 — Web App**
FastAPI backend wrapping the scanner, frontend for repo input and file upload, deployed to Azure Container Apps via GitHub Actions CI/CD. Anyone can scan a pipeline from a browser without installing anything.

**Phase 3 — Expansion**
Jenkins support, AWS CodePipeline, 20+ rule library, rate limiting on web app, Homebrew formula.

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
| `__line_` hidden keys picked up by hardcoded secrets rule | Added `startswith("__line_")` filter |
| Line numbers returning 0 | Rewrote `check()` to access env dicts directly without stripping hidden keys |
| GitLab curl command parsed as dict by PyYAML | Colon in `Authorization: Bearer` triggered YAML key parsing — wrapped command in single quotes in fixture |
| Azure DevOps FS009/FS010 not firing | `script:` field is a string block not a list in Azure — fix pending |