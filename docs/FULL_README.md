# FlowSec — Full Documentation

## What is this project?

FlowSec is a published Python command-line security tool that scans CI/CD pipeline configurations for attack vectors. Point it at a GitHub repository, a GitLab project, or an Azure DevOps pipeline and it pulls the config, runs 26 security rules against it, and returns a prioritized list of findings — each mapped to a MITRE ATT&CK technique and an OWASP CICD Top 10 category.

**Homebrew (macOS):**

```bash
brew install VanshBhardwaj1945/flowsec/flowsec
```

**PyPI:**

```bash
pip install flowsec
export GITHUB_TOKEN=your_token
flowsec scan --github --repo owner/repo
```

---

## Why I built this

Most security tooling audits application code. Almost nothing audits the pipelines that build, test, and deploy that code — and those pipelines are one of the most dangerous attack surfaces in a modern software organization.

A CI/CD pipeline runs automatically on every push. It has access to production secrets, cloud credentials, and deployment infrastructure. It pulls dependencies from external sources. It often runs with elevated permissions. And in most organizations, pipeline config files are treated as an afterthought — written once, never reviewed, sitting in git forever.

FlowSec treats pipeline configuration files the same way a penetration tester would — as configs to audit for attack vectors before an attacker finds them first.

---

## Stack

| Tool | Purpose |
|---|---|
| Python 3.11 | Core language |
| PyGithub | GitHub API — fetches workflow files from target repos |
| python-gitlab | GitLab API — fetches .gitlab-ci.yml from remote projects |
| httpx | Azure DevOps REST API — fetches azure-pipelines.yml |
| PyYAML | Parses YAML pipeline configs into Python dicts with line tracking |
| rich | Colored terminal output — findings tables, risk score summary |
| anthropic | Claude API — generates AI attack narratives per finding |
| jinja2 | HTML report templating (autoescape enabled) |
| python-dotenv | Loads API credentials from .env locally |
| ruff | Linting and formatting |
| mypy | Type checking |
| bandit | Scans FlowSec's own Python code for security issues |
| hatch | Build and PyPI publishing |

---

## Project Structure

```
FlowSec/
├── .github/
│   └── workflows/
│       ├── publish.yml          — PyPI publish on v* tag push (OIDC trusted publishing)
│       └── security.yml         — Security scans on every push/PR (gitleaks, bandit, pip-audit, self-scan)
├── src/
│   └── pipelineguard/
│       ├── cli.py               — argparse CLI, Rich terminal output
│       ├── scanner.py           — All scan_* functions and remote API fetchers
│       ├── parser.py            — YAML to Python dict with line number tracking
│       ├── report.py            — HTML report generation via Jinja2
│       ├── ai_narrative.py      — Claude API integration with local MD5 cache
│       ├── scoring.py           — Risk score: 0-100, diminishing returns + exponential normalization
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
│           ├── github_context_injection.py    — FS011
│           ├── missing_env_protection.py      — FS012
│           ├── workflow_dispatch_injection.py — FS013
│           ├── mutable_container_image.py     — FS014
│           ├── persist_credentials.py         — FS015
│           ├── workflow_run_trigger.py        — FS016
│           ├── continue_on_error_security.py  — FS017
│           ├── secret_as_cli_arg.py           — FS018
│           ├── unverified_install_script.py   — FS019
│           ├── container_runs_as_root.py      — FS020
│           ├── secrets_in_build_args.py       — FS021
│           ├── broad_artifact_upload.py       — FS022
│           ├── insecure_curl.py               — FS023
│           ├── privileged_docker.py           — FS024
│           ├── env_vars_in_logs.py            — FS025
│           └── deploy_all_branches.py         — FS026
├── tests/
│   ├── fixtures/
│   │   ├── github_all_vulns.yml    — GitHub Actions fixture (every FS rule fires)
│   │   ├── gitlab_all_vulns.yml    — GitLab CI fixture (every applicable rule fires)
│   │   └── azure_all_vulns.yml     — Azure DevOps fixture (every applicable rule fires)
│   ├── test_github_rules.py
│   ├── test_gitlab_rules.py
│   └── test_azure_rules.py
├── docs/
│   ├── FULL_README.md           — This file
│   └── screenshots/
│       └── flowsec-logo.png
├── homebrew-tap/
│   └── Formula/
│       └── flowsec.rb           — Homebrew formula (canonical copy — live tap is VanshBhardwaj1945/homebrew-flowsec)
├── pyproject.toml
├── PYPI_README.md               — PyPI page description (no images, clean text)
├── README.md                    — GitHub repo README (with logo, badges)
├── SECURITY.md                  — Responsible disclosure policy
├── AGENTS.md                    — Guide for AI agents working on this codebase
└── LICENSE                      — MIT License
```

---

## Architecture

Five layers. Each has one job and hands its output to the next.

**Layer 1 — Connect**
For GitHub, PyGithub fetches every `.yml` and `.yaml` file inside `.github/workflows/` using a personal access token. For GitLab, `python-gitlab` fetches `.gitlab-ci.yml` from the project's default branch. For Azure DevOps, `httpx` calls the Azure DevOps REST API with a PAT. All paths produce raw YAML text. For local file scans, the file is read directly.

**Layer 2 — Parse**
A custom PyYAML loader called `LineLoader` (a subclass of `yaml.SafeLoader`) converts raw YAML into a Python dictionary while preserving line number information for every key — stored as hidden `__line_KEYNAME__` entries. This is what allows findings to report the exact line a hardcoded secret lives on rather than just the file name.

**Layer 3 — Scan**
The rule engine calls `check(config, file_path, platform)` on every rule in the `RULES` list. The `platform` parameter (`"github"`, `"gitlab"`, or `"azure"`) tells each rule which part of the config to inspect. All findings from all rules across all files are collected into one flat list.

**Layer 4 — Score**
Findings are aggregated into a risk score (0-100) using severity-weighted diminishing returns:
- Each additional finding of the same severity contributes less than the previous: `weight / sqrt(n)`
- Weights: CRITICAL=10, HIGH=5, MEDIUM=3, LOW=1
- Normalized via exponential decay: `round(100 * (1 - e^(-raw/30)))`
- Score asymptotes to 100 — it cannot exceed it

**Layer 5 — Output**
Three output modes: the terminal gets a Rich colored table with severity badges, MITRE and OWASP columns, and a summary panel with the 0-100 risk score. An HTML report is generated with `--output`. AI attack narratives are generated with `--ai` via the Claude API and cached locally in `~/.flowsec_cache.json`.

---

## Platform Support

| Platform | File scan | Remote repo scan | Required token |
|---|---|---|---|
| GitHub Actions | `--github --file workflow.yml` | `--github --repo owner/repo` | `GITHUB_TOKEN` (for remote) |
| GitLab CI | `--gitlab --file .gitlab-ci.yml` | `--gitlab --repo namespace/project` | `GITLAB_TOKEN` (for remote) |
| Azure DevOps | `--azure --file azure-pipelines.yml` | `--azure --repo org/project` | `AZURE_DEVOPS_TOKEN` (remote only — Azure requires auth even for public projects) |

Rules that are GitHub-specific — FS002, FS003, FS004, FS005, FS008, FS011, FS012, FS013, FS015, FS016 — return no findings for GitLab and Azure. Rules that apply to all platforms adapt their field lookups based on the platform parameter.

---

## Rule Engine

Built around three components in `src/pipelineguard/rules/base.py`.

**Severity** is an enum — CRITICAL, HIGH, MEDIUM, LOW. Using an enum instead of plain strings means a typo throws an error immediately rather than silently breaking a report.

**Finding** is a dataclass every rule returns when it detects a problem. Every finding has the same shape regardless of which rule or platform produced it: rule ID, title, severity, description, remediation, MITRE technique, OWASP category, file path, line number, and AI narrative.

**BaseRule** is an abstract base class every rule inherits from. It enforces that every rule implements `check(config, file_path, platform)`. If a new rule is written without it, Python throws an error at import time.

Adding a new rule is four steps: create a file in `src/pipelineguard/rules/`, inherit from `BaseRule`, implement `check()`, add it to `RULES` in `scanner.py`. Nothing else changes. Next available ID: **FS027**.

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
| FS011 | GitHub Context Injection — Untrusted Event Data in Run Step | CRITICAL | T1059.004 | CICD-SEC-4 | GitHub |
| FS012 | Missing Environment Protection — Deploy Job Has No Approval Gate | HIGH | T1078 | CICD-SEC-5 | GitHub |
| FS013 | Workflow Dispatch Injection — Unvalidated Input in Shell Command | CRITICAL | T1059 | CICD-SEC-9 | GitHub |
| FS014 | Mutable Container Image — Unpinned Image Tag in Pipeline | MEDIUM | T1195.001 | CICD-SEC-3 | All |
| FS015 | Persist Credentials — GitHub Token Remains in Git Config After Checkout | MEDIUM | T1552.001 | CICD-SEC-6 | GitHub |
| FS016 | workflow_run Trigger — Privileged Execution from Untrusted Workflow | HIGH | T1059 | CICD-SEC-1 | GitHub |
| FS017 | Security Scan Silenced — Failures Suppressed with continue-on-error | MEDIUM | T1562.001 | CICD-SEC-7 | All |
| FS018 | Secret as CLI Argument — Credential Exposed in Process List | HIGH | T1552 | CICD-SEC-6 | All |
| FS019 | Unverified Install Script — Remote Code Fetched and Executed Directly | HIGH | T1195.002 | CICD-SEC-3 | All |
| FS020 | Container Running as Root — Elevated Privilege in Pipeline | HIGH | T1611 | CICD-SEC-7 | All |
| FS021 | Secret in Docker Build Argument — Credential Stored in Image History | HIGH | T1552.001 | CICD-SEC-6 | All |
| FS022 | Broad Artifact Upload — Entire Workspace Exposed as Artifact | MEDIUM | T1560 | CICD-SEC-9 | All |
| FS023 | Insecure curl — SSL Verification Disabled in Pipeline | HIGH | T1071 | CICD-SEC-3 | All |
| FS024 | Privileged Docker Container — Full Host Access Granted in Pipeline | CRITICAL | T1611 | CICD-SEC-7 | All |
| FS025 | Environment Variables Printed to Logs — Secrets Exposed in Pipeline Output | MEDIUM | T1552.001 | CICD-SEC-6 | All |
| FS026 | Unguarded Deploy — Deployment Job Runs on Untrusted Branches | HIGH | T1078 | CICD-SEC-1 | All |

### Rule Details

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

**FS011** flags `${{ github.event.issue.title }}`, `${{ github.head_ref }}`, `${{ github.event.pull_request.body }}`, and similar untrusted GitHub context expressions used directly inside `run:` steps. These values come from external actors and become arbitrary command injection if interpolated unquoted into shell.

**FS012** flags deployment jobs — identified by keywords like `deploy`, `release`, `prod` in the job name — that have no `environment:` key. Without GitHub Environments, deployments to production happen automatically with no human approval gate.

**FS013** flags `workflow_dispatch` workflows where `${{ inputs.* }}` appears unquoted in shell commands. An attacker with access to trigger the workflow can inject arbitrary shell commands through the input fields.

**FS014** flags container images referenced in pipeline configs without a digest pin. Tags like `:latest` or `:v1` are mutable. Only a `@sha256:` digest guarantees the exact image bytes your pipeline will run.

**FS015** flags `actions/checkout` steps that do not explicitly set `persist-credentials: false`. The GitHub token is written to the local git config for the duration of the job — any step that runs afterward can read it.

**FS016** flags `workflow_run:` as a trigger. Like `pull_request_target`, `workflow_run` runs in the context of the base branch with access to secrets, but is triggered by a workflow from a fork.

**FS017** flags security scanning steps — Trivy, Snyk, Bandit, Semgrep, Checkov, Grype, Gitleaks — that have `continue-on-error: true` (GitHub), `allow_failure: true` (GitLab), or `continueOnError: true` (Azure). Silencing scanner failures means a finding that would block a deploy is silently swallowed.

**FS018** flags shell commands where a secret or credential is passed as a named CLI flag — `--token`, `--password`, `--api-key` — with a value from the secrets context. CLI arguments are visible to any process that can read `/proc/<pid>/cmdline` on Linux.

**FS019** flags `curl ... | bash` and `wget ... | bash` patterns — fetching a remote script and piping it directly to a shell interpreter without any checksum verification.

**FS020** flags `docker run` commands without a `--user` flag or with `--user root`. Containers running as root have elevated privileges that expand the blast radius if the pipeline is compromised.

**FS021** flags `docker build --build-arg` commands where the argument name matches credential patterns. Build arguments are stored in image layer history and readable via `docker history`.

**FS022** flags artifact upload steps that use overly broad path patterns — `.`, `*`, `**` — that would upload the entire workspace. Workspaces can contain `.env` files, build outputs with embedded secrets, and any files written by previous steps.

**FS023** flags `curl -k` and `curl --insecure` in run commands. Disabling SSL verification allows a man-in-the-middle attacker to serve malicious content to your pipeline.

**FS024** flags `docker run --privileged`, `--cap-add SYS_ADMIN`, and `--security-opt seccomp=unconfined`. A privileged container has full access to the host kernel and devices — it can escape the container boundary entirely.

**FS025** flags `env`, `printenv`, and `echo $VARIABLE` in pipeline steps. These dump environment variables to pipeline logs which are visible to all repo contributors.

**FS026** flags deployment jobs that run without branch guards — on any platform. Without branch guards, a push to any feature branch can trigger a production deployment.

---

## CLI

```bash
# GitHub Actions — remote repo
flowsec scan --github --repo owner/repo

# GitHub Actions — local file
flowsec scan --github --file .github/workflows/ci.yml

# GitLab CI — remote project (requires GITLAB_TOKEN)
flowsec scan --gitlab --repo namespace/project

# GitLab CI — local file
flowsec scan --gitlab --file .gitlab-ci.yml

# Azure DevOps — remote (requires AZURE_DEVOPS_TOKEN)
flowsec scan --azure --repo org/project

# Azure DevOps — local file
flowsec scan --azure --file azure-pipelines.yml

# HTML report
flowsec scan --github --repo owner/repo --output report.html

# AI attack narratives (requires ANTHROPIC_API_KEY)
flowsec scan --github --repo owner/repo --ai

# Pipeline gate — exit code 1 if findings at or above threshold
flowsec scan --github --repo owner/repo --fail-on critical

# Suppress specific rules
flowsec scan --github --repo owner/repo --ignore FS006 --ignore FS011

# Everything at once
flowsec scan --github --repo owner/repo --ai --output report.html --fail-on high --ignore FS006
```

---

## Rule Suppression

**Via CLI flag:**

```bash
flowsec scan --github --repo owner/repo --ignore FS006 --ignore FS011
```

**Via config file** — create `.flowsec.yml` in the directory where you run FlowSec:

```yaml
ignore:
  - rule_id: FS006
    reason: "We use external timeout management"
  - rule_id: FS011
    reason: "Branch protection managed at org level"
```

Both methods can be used together. The `reason` field is optional but recommended for audit trails.

---

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
        run: flowsec scan --github --file .github/workflows/ci.yml --fail-on critical
```

`--fail-on` exits with code 1 if findings at or above the threshold are found. Supported: `critical`, `high`, `medium`, `low`.

---

## AI Attack Narratives

When `--ai` is passed, FlowSec calls the Claude API per finding and generates a structured narrative:

```
Attack Vector: how the attacker exploits this specific misconfiguration
What They Gain: what access or capability they obtain
Blast Radius: realistic worst case impact
Ways to Fix: remediation guidance
```

Narratives are cached in `~/.flowsec_cache.json` using a content hash of the finding's rule ID and description. The same finding is never sent to the API twice.

---

## HTML Report

Generated with `--output report.html`. A self-contained single file — no internet connection needed.

- Summary cards per severity and 0-100 risk score — clickable to filter
- Findings overview table with MITRE and OWASP columns
- Expandable finding cards with description, remediation, and AI narrative
- OWASP tags in green, MITRE tags in blue
- PDF export button with print-optimized CSS

---

## Risk Score (0-100)

The risk score uses severity-weighted diminishing returns normalized to 0-100:

1. For each severity level, each additional finding contributes `weight / sqrt(n)` — finding the same issue in 10 jobs is worse than 1 job, but not 10x worse
2. Weights: CRITICAL=10, HIGH=5, MEDIUM=3, LOW=1
3. Final normalization: `round(100 * (1 - e^(-raw/30)))` — asymptotes to 100, never exceeds it

A single critical finding scores ~28. A heavily vulnerable real pipeline scores ~90-97. A score of 100 is practically unreachable.

---

## Security Design

FlowSec is built to the same standard it enforces.

- **Own CI:** gitleaks (secret scanning), bandit (SAST), pip-audit (dependency CVEs), and FlowSec self-scan on every push
- **PyPI publishing:** OIDC trusted publishing — no long-lived API tokens. Sigstore attestations generated automatically by PyPI
- **GitHub Actions:** all actions pinned to commit SHAs, `persist-credentials: false`, explicit least-privilege permissions, timeouts on every job
- **Branch protection on main:** force push blocked, direct deletion blocked, 4 required status checks before merge
- **YAML parsing:** `LineLoader` is a subclass of `yaml.SafeLoader` — arbitrary code execution via YAML is not possible
- **HTML reports:** Jinja2 `autoescape=select_autoescape(["html"])` — XSS from finding content is prevented
- **Tokens:** loaded from environment variables / `.env` only — never passed as CLI arguments
- **Remote HTTP:** explicit `timeout=15` on all external requests — no indefinite hangs
- **Responsible disclosure:** see `SECURITY.md`

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

## Environment Variables

| Variable | Required for | Where to get it |
|---|---|---|
| `GITHUB_TOKEN` | `--github --repo` | GitHub Settings → Developer settings → Personal access tokens |
| `GITLAB_TOKEN` | `--gitlab --repo` | GitLab Settings → Access Tokens |
| `AZURE_DEVOPS_TOKEN` | `--azure --repo` | Azure DevOps → User Settings → Personal Access Tokens |
| `ANTHROPIC_API_KEY` | `--ai` | console.anthropic.com |

Store these in a `.env` file in the project root. FlowSec loads it automatically via `python-dotenv`. The `.env` file is gitignored.

---

## Roadmap

**Phase 2 — Expansion**
Jenkins support, AWS CodePipeline, 20+ rule library.

---

## Known Issues and Design Decisions

| Issue | Resolution |
|---|---|
| PyYAML converts `on` to Python `True` | Known behavior — no rules inspect the trigger block |
| `__line_` keys match credential patterns | All rules skip keys starting with `__line_` |
| Azure DevOps API requires auth for public projects | `AZURE_DEVOPS_TOKEN` is required even for public repos — Azure redirects unauthenticated requests to login |
| GitLab curl `Authorization: Bearer` parsed as dict | Colon in value triggers YAML key parsing — fixtures wrap in single quotes |
| hatch 1.14.1 breaks with virtualenv 21.x | `virtualenv<21` must be pinned alongside hatch — virtualenv 21 removed `propose_interpreters` |
| cosign sign-blob fails with glob + multiple files in v3.x | Removed cosign; PyPI OIDC trusted publishing generates Sigstore attestations natively |
| Node.js 20 action deprecation (June 16, 2026) | `FORCE_JAVASCRIPT_ACTIONS_TO_NODE24: "true"` set in both workflow files |
