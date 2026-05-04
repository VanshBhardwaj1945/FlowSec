# FlowSec — Full Documentation

## What is this project?

FlowSec is a published Python command line security tool that scans CI/CD pipeline configurations for attack vectors. Point it at a GitHub repository, a GitLab CI file, or an Azure DevOps pipeline and it pulls the config, runs 13 security rules against it, and hands back a prioritized list of findings — each mapped to a MITRE ATT&CK technique and an OWASP CICD Top 10 category.

```bash
pip install flowsec
flowsec scan --repo owner/repo
```

---

## Why I built this

Most security tooling audits application code. Almost nothing audits the pipelines that build, test, and deploy that code — and those pipelines are one of the most dangerous attack surfaces in a modern software organization.

A CI/CD pipeline runs automatically on every push. It has access to production secrets, cloud credentials, and deployment infrastructure. It pulls dependencies from external sources. It often runs with elevated permissions. And in most organizations, the pipeline config files are treated as an afterthought — written once, never reviewed, sitting in git forever.

FlowSec treats pipeline configuration files the same way a penetration tester would — as configs to audit for attack vectors before an attacker finds them first.

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
| python-dotenv | Loads API credentials from .env locally |
| ruff | Linting and formatting |
| mypy | Type checking |
| bandit | Scans FlowSec's own Python code for security issues |
| hatch | Build and PyPI publishing |
| Docker | Multi-stage container packaging |

---

## Project Structure

```
FlowSec/
├── .devcontainer/
│   └── devcontainer.json        — GitHub Codespace config
├── .github/
│   └── workflows/
│       └── publish.yml          — PyPI publish on tag push
├── src/
│   └── pipelineguard/
│       ├── cli.py               — argparse CLI, Rich terminal output
│       ├── scanner.py           — GitHub API connection and rule orchestration
│       ├── parser.py            — YAML to Python dict with line number tracking
│       ├── report.py            — HTML report generation via Jinja2
│       ├── ai_narrative.py      — Claude API integration with local caching
│       └── rules/
│           ├── base.py                        — BaseRule ABC, Finding dataclass, Severity enum
│           ├── hardcoded_secrets.py           — FS001
│           ├── unpinned_actions.py            — FS002
│           ├── excessive_permissions.py       — FS003
│           ├── missing_oidc.py                — FS004
│           ├── pull_request_target.py         — FS005
│           ├── missing_timeout.py             — FS006
│           ├── self_hosted_runner.py          — FS007
│           ├── artifact_signing.py            — FS008
│           ├── dependency_pinning.py          — FS009
│           ├── secrets_in_run.py              — FS010
│           ├── missing_branch_protection.py   — FS011
│           ├── missing_env_protection.py      — FS012
│           ├── workflow_dispatch_injection.py — FS013
│           ├── container_runs_as_root.py      — FS020
│           ├── secrets_in_build_args.py       — FS021
│           ├── insecure_curl.py               — FS023
│           └── env_vars_in_logs.py            — FS025
├── tests/
│   └── fixtures/
│       ├── sample_workflow_vulnerable.yml
│       ├── sample_workflow_clean.yml
│       ├── sample_gitlab_vulnerable.yml
│       └── sample_azure_vulnerable.yml
├── pyproject.toml
├── Makefile
├── Dockerfile
└── docker-compose.yml
```

---

## Architecture

Five layers. Each has one job and hands its output to the next.

**Layer 1 — Connect**
For GitHub, PyGithub fetches every `.yml` and `.yaml` file inside `.github/workflows/` using a personal access token. For GitLab and Azure DevOps, local files are read directly. All three paths produce raw YAML text.

**Layer 2 — Parse**
A custom PyYAML loader called `LineLoader` converts raw YAML into a Python dictionary while preserving line number information for every key — stored as hidden `__line_KEYNAME__` entries. This is what allows findings to report the exact line a hardcoded secret lives on rather than just the file name.

**Layer 3 — Scan**
The rule engine calls `check(config, file_path, platform)` on every rule in the `RULES` list. The `platform` parameter tells each rule which part of the config to inspect — one rule file handles all three platforms. All findings from all rules across all files are collected into one flat list.

**Layer 4 — Score**
Findings are aggregated into a weighted risk score — CRITICAL×10, HIGH×5, MEDIUM×3, LOW×1.

**Layer 5 — Output**
Three output modes. The terminal gets a Rich colored table with severity badges, MITRE and OWASP columns, and a summary panel. An HTML report is generated with `--output`. AI attack narratives are generated with `--ai` via the Claude API and cached locally.

---

## Platform Support

| Platform | Flag | Pipeline File |
|---|---|---|
| GitHub Actions | `--repo owner/repo` or `--file workflow.yml` | `.github/workflows/*.yml` |
| GitLab CI | `--gitlab .gitlab-ci.yml` | `.gitlab-ci.yml` |
| Azure DevOps | `--azure azure-pipelines.yml` | `azure-pipelines.yml` |

Rules that are GitHub-specific — FS002, FS003, FS004, FS005, FS008, FS012, FS013 — return no findings for GitLab and Azure. Rules that apply to all platforms — FS001, FS006, FS007, FS009, FS010, FS020, FS021, FS023, FS025 — adapt their field lookups based on the platform parameter.

---

## Rule Engine

Built around three components in `src/pipelineguard/rules/base.py`.

**Severity** is an enum — CRITICAL, HIGH, MEDIUM, LOW. Using an enum instead of plain strings means a typo throws an error immediately rather than silently breaking a report.

**Finding** is a dataclass every rule returns when it detects a problem. Every finding has the same shape regardless of which rule or platform produced it — rule ID, title, severity, description, remediation, MITRE technique, OWASP category, file path, line number, and AI narrative.

**BaseRule** is an abstract base class every rule inherits from. It enforces that every rule implements `check(config, file_path, platform)`. If a new rule is written without it, Python throws an error at import time.

Adding a new rule is four steps: create a file in `src/pipelineguard/rules/`, inherit from `BaseRule`, implement `check()`, add it to `RULES` in `scanner.py`. Nothing else changes.

---

## Rules

| ID | Rule | Severity | MITRE | OWASP | Platforms |
|---|---|---|---|---|---|
| FS001 | Hardcoded Secret — Plaintext Credential in Workflow | CRITICAL | T1552.001 | CICD-SEC-6 | All |
| FS002 | Unpinned Action — Supply Chain Attack Vector | CRITICAL | T1195.001 | CICD-SEC-3 | GitHub |
| FS003 | Excessive Permissions — Overprivileged Workflow Token | HIGH | T1078 | CICD-SEC-5 | GitHub |
| FS004 | Missing OIDC — Long-Lived Cloud Credential in Use | HIGH | T1552.004 | CICD-SEC-6 | GitHub |
| FS005 | Pull Request Target — Secrets Exposed to Fork Code | CRITICAL | T1611 | CICD-SEC-4 | GitHub |
| FS006 | Missing Timeout — Job Runs Up to 6 Hours Unchecked | LOW | T1499 | CICD-SEC-10 | All |
| FS007 | Self-Hosted Runner — Persistent Environment Risk | HIGH | T1053 | CICD-SEC-7 | All |
| FS008 | Missing Artifact Signing — No Tamper Protection | MEDIUM | T1553 | CICD-SEC-8 | GitHub |
| FS009 | Unpinned Dependency — Package Installed Without Version Lock | HIGH | T1195.002 | CICD-SEC-3 | All |
| FS010 | Secret in Run Command — Plaintext Credential in Shell Step | CRITICAL | T1552.001 | CICD-SEC-6 | All |
| FS012 | Missing Environment Protection — Deploy Job Has No Approval Gate | HIGH | T1078 | CICD-SEC-5 | GitHub |
| FS013 | Workflow Dispatch Injection — Unvalidated Input in Shell Command | CRITICAL | T1059 | CICD-SEC-9 | GitHub |
| FS020 | Container Running as Root — Elevated Privilege in Pipeline | HIGH | T1611 | CICD-SEC-7 | All |
| FS021 | Secret in Docker Build Argument — Credential Stored in Image History | HIGH | T1552.001 | CICD-SEC-6 | All |
| FS023 | Insecure curl — SSL Verification Disabled in Pipeline | HIGH | T1071 | CICD-SEC-3 | All |
| FS025 | Environment Variables Printed to Logs — Secrets Exposed in Pipeline Output | MEDIUM | T1552.001 | CICD-SEC-6 | All |

**FS001** scans env variables across all platforms for suspicious names — API_KEY, PASSWORD, TOKEN, SECRET — whose values don't reference a secret manager. `${{ secrets.X }}` is safe. A hardcoded string is not.

**FS002** flags any `uses:` field not pinned to a full 40-character git commit hash. Tags like `@v3` and branches like `@main` are mutable — an attacker who compromises the action repo can push malicious code that every unpinned pipeline pulls automatically. Same attack pattern as SolarWinds.

**FS003** flags `write-all`, `read-all`, and missing permissions blocks where GitHub's permissive defaults apply. A token with write-all can push code, modify releases, and exfiltrate secrets.

**FS004** detects pipelines connecting to AWS, Azure, or GCP without OIDC. Long-lived credentials exist until manually rotated. OIDC tokens expire in 15 minutes — nothing to steal, nothing to rotate.

**FS005** flags `pull_request_target` combined with `actions/checkout`. This trigger runs with full access to secrets even when triggered by a fork — combined with checking out PR code, an attacker can execute arbitrary commands in your trusted environment.

**FS006** flags jobs without timeout configuration. GitHub default is 6 hours, GitLab is 1 hour, Azure uses `timeoutInMinutes`. A stuck job or deliberate attack burns runner minutes and blocks other workflows.

**FS007** flags self-hosted runners across all platforms. GitHub checks `runs-on: self-hosted`, GitLab checks `tags:`, Azure checks custom agent pool names. Self-hosted runners persist between jobs and can be poisoned by malicious workflows.

**FS008** flags pipelines that publish Docker images, PyPI packages, or GitHub releases without cryptographic signing via Sigstore or SLSA.

**FS009** scans `run:` on GitHub and `script:` on GitLab and Azure for `pip install`, `npm install`, and `yarn add` without version pins. Unpinned installs are vulnerable to dependency confusion attacks.

**FS010** scans shell commands for credential patterns — `password=`, `token=`, `Authorization: Bearer` — followed by values that don't reference a secret manager. Credentials in shell commands appear in pipeline logs and git history.


**FS012** flags deployment jobs — identified by keywords like `deploy`, `release`, `prod` in the job name — that have no `environment:` key. Without GitHub Environments, deployments to production happen automatically with no human approval.

**FS013** flags `workflow_dispatch` workflows where `${{ inputs.* }}` appears unquoted in shell commands. An attacker with access to trigger the workflow can inject arbitrary shell commands through the input fields.

**FS020** flags `docker run` commands without a `--user` flag or with `--user root`. Containers running as root have elevated privileges that expand the blast radius if the pipeline is compromised.

**FS021** flags `docker build --build-arg` commands where the argument name matches credential patterns — API_KEY, TOKEN, PASSWORD. Build arguments are stored in image layer history and readable by anyone with access to the image via `docker history`.

**FS023** flags `curl -k` and `curl --insecure` in run commands. Disabling SSL verification allows a man-in-the-middle attacker to intercept the connection and serve malicious content — scripts, binaries, or dependencies — to your pipeline.

**FS025** flags commands like `env`, `printenv`, and `echo $VARIABLE` in pipeline steps. These dump environment variables to pipeline logs which are visible to all repo contributors and sometimes publicly accessible on open source repos.

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

# Ignore Findings
flowsec scan --repo owner/repo --ignore FS006 --ignore FS011

# Everything at once
flowsec scan --repo owner/repo --ai --output report.html --fail-on high --ignore FS006
```

---

## Rule Suppression

FlowSec supports suppressing specific rules in two ways.

**Via CLI flag** — pass `--ignore` one or more times:

```bash
flowsec scan --repo owner/repo --ignore FS006 --ignore FS011
```

**Via config file** — create `.flowsec.yml` in the directory where you run FlowSec:

```yaml
ignore:
  - rule_id: FS006
    reason: "We use external timeout management"
  - rule_id: FS011
    reason: "Branch protection managed at org level"
```

Both methods can be used together — FlowSec merges them automatically. The `reason` field is optional but recommended for audit trails. The config file approach is better for teams since it lives in the repo and is reviewable in git history.

## Pipeline Gate

Add FlowSec to your own pipeline to automatically block PRs that introduce security misconfigurations:

```yaml
name: FlowSec Security Scan
on: [push, pull_request]
jobs:
  security:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Install FlowSec
        run: pip install flowsec
      - name: Run FlowSec
        run: flowsec scan --file .github/workflows/ --fail-on critical
```

`--fail-on` exits with code 1 if findings at or above the threshold are found. Supported thresholds: `critical`, `high`, `medium`, `low`.

---

## AI Attack Narratives

When `--ai` is passed, FlowSec calls the Claude API per finding and generates a structured narrative:

```
Attack Vector: how the attacker exploits this specific misconfiguration
What They Gain: what access or capability they obtain
Blast Radius: realistic worst case impact
```

Narratives are cached in `~/.flowsec_cache.json` using an MD5 hash of the finding's rule ID and description. The same finding is never sent to the API twice — subsequent scans return cached narratives instantly at zero cost.

---

## HTML Report

Generated with `--output report.html`. A self-contained single file — no internet connection needed.

- Summary cards per severity and overall risk score — clickable to filter
- Findings overview table with MITRE and OWASP columns
- Expandable finding cards with description, remediation, and AI narrative
- OWASP tags in green, MITRE tags in blue
- PDF export button with print-optimized CSS

---

## Real Findings — cloud-resume-challenge-azure

```
[CRITICAL] FS002 - Unpinned Action — Supply Chain Attack Vector
  File: .github/workflows/backend.main.yaml
  Action 'actions/checkout@v4' is not pinned to a commit hash

[CRITICAL] FS002 - Unpinned Action — Supply Chain Attack Vector
  File: .github/workflows/frontend.main.yaml
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

13 findings across 2 workflow files on a real production project.

---

## Roadmap

**Phase 2 — Expansion**
Jenkins support, AWS CodePipeline, 20+ rule library, Homebrew formula.

---

## Issues Resolved

| Issue | Resolution |
|---|---|
| PyYAML converts `on` to Python `True` | Known behavior — no rules inspect the trigger block |
| pip install blocked by macOS system Python | Created venv with `python3 -m venv .venv` |
| venv created at wrong path | Deleted and recreated at `.venv` |
| Click Arena has no `.github/workflows/` folder | Uses Jenkins — tested against `cloud-resume-challenge-azure` |
| 404 on first scanner test | Wrong repo — switched to one using GitHub Actions |
| Python 3.14 editable install not creating `.pth` file | Hatchling compatibility issue — fixed with `PYTHONPATH` in `.zshrc` |
| GitHub push protection blocked commit | Real token in `.env.example` — revoked and replaced with placeholder |
| `__line_` keys picked up by hardcoded secrets rule | Added `startswith("__line_")` filter |
| Line numbers returning 0 | Rewrote `check()` to access env dicts directly |
| GitLab curl command parsed as dict | Colon in `Authorization: Bearer` triggered YAML key parsing — wrapped in single quotes |
