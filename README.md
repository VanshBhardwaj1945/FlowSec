<p align="center">
  <img src="docs/screenshots/flowsec-logo.png" alt="FlowSec" width="520" />
</p>

<p align="center">
  <a href="https://codespaces.new/VanshBhardwaj1945/FlowSec"><img src="https://github.com/codespaces/badge.svg" alt="Open in GitHub Codespaces" /></a>
  <a href="https://badge.fury.io/py/flowsec"><img src="https://badge.fury.io/py/flowsec.svg" alt="PyPI version" /></a>
</p>

> A Python security tool that scans CI/CD pipeline configurations for attack vectors across GitHub Actions, GitLab CI, and Azure DevOps. Every finding maps to a MITRE ATT&CK technique and OWASP CICD Top 10 category.
>
> The pipeline is the attack surface. FlowSec treats it that way.

**[Full documentation](docs/FULL_README.md)**

---

## Quick Start


Click the Codespaces button above to run FlowSec in your browser with zero setup.

**Homebrew (macOS):**

```bash
brew install VanshBhardwaj1945/flowsec/flowsec
```

Or tap once then install:

```bash
brew tap VanshBhardwaj1945/flowsec
brew install flowsec
```

**PyPI:**

```bash
pip install flowsec                # local file/directory scanning
pip install "flowsec[remote]"      # + remote repo scanning (GitHub/GitLab/Azure APIs)
pip install "flowsec[ai]"          # + AI attack narratives
flowsec scan --github --dir .
```

Remote GitHub scanning works unauthenticated for public repos; set `GITHUB_TOKEN` for private repos and higher rate limits.

Or run from source:

```bash
git clone https://github.com/VanshBhardwaj1945/FlowSec.git
cd FlowSec
python3 -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
cp .env.example .env
# Add your GITHUB_TOKEN to .env
```

---

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

---

## What it catches


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
| FS027 | Docker Socket Mounted — Full Host Control from Pipeline | CRITICAL | T1611 | CICD-SEC-7 | All |
| FS028 | Credential in Git URL — Token Leaked to Logs and History | HIGH | T1552.001 | CICD-SEC-6 | All |
| FS029 | github-script Injection — Untrusted Event Data in Inline Script | CRITICAL | T1059.004 | CICD-SEC-4 | GitHub |
| FS030 | secrets: inherit — All Secrets Passed to Called Workflow | MEDIUM | T1078 | CICD-SEC-5 | GitHub |
| FS031 | Cache Poisoning Risk — Cache Used With Privileged Trigger | HIGH | T1195.001 | CICD-SEC-3 | GitHub |
| FS032 | Unpinned Remote Include — External Pipeline Config Pulled at Runtime | HIGH | T1195.001 | CICD-SEC-3 | GitLab, Azure |
| FS033 | Unsecure Commands Enabled — Deprecated set-env Injection Re-Enabled | HIGH | T1059.004 | CICD-SEC-4 | GitHub |
| FS034 | Plain-HTTP Download — Unencrypted Fetch in Pipeline | MEDIUM | T1071 | CICD-SEC-3 | All |
| FS035 | Environment File Injection — Untrusted Data Written to GITHUB_ENV | HIGH | T1059.004 | CICD-SEC-4 | GitHub |
| FS036 | Persist Credentials — Azure Checkout Leaves Token in Git Config | MEDIUM | T1552.001 | CICD-SEC-6 | Azure |
| FS037 | Obfuscated Execution — Encoded Payload Piped to a Shell | MEDIUM | T1027 | CICD-SEC-3 | All |
| FS038 | Docker-in-Docker Service — Privileged Runner Required | HIGH | T1611 | CICD-SEC-7 | GitLab |

---

---

## Platforms supported


| Platform | File scan | Directory scan | Remote repo scan |
|---|---|---|---|
| GitHub Actions | `flowsec scan --github --file workflow.yml` | `flowsec scan --github --dir .` | `flowsec scan --github --repo owner/repo` |
| GitLab CI | `flowsec scan --gitlab --file .gitlab-ci.yml` | `flowsec scan --gitlab --dir .` | `flowsec scan --gitlab --repo namespace/project` |
| Azure DevOps | `flowsec scan --azure --file azure-pipelines.yml` | `flowsec scan --azure --dir .` | `flowsec scan --azure --repo org/project` |

`--dir` scans a repo checkout: for GitHub it picks up everything in `.github/workflows/`, for GitLab and Azure it finds `.gitlab-ci.yml` / `azure-pipelines.yml`, and it falls back to every `.yml`/`.yaml` in the directory.

---

---

## Output formats


| Format | Command | Use it for |
|---|---|---|
| Terminal table (default) | `flowsec scan --github --dir .` | Reading findings locally |
| JSON | `flowsec scan --github --dir . --format json` | Scripting and jq pipelines |
| SARIF 2.1.0 | `flowsec scan --github --dir . --format sarif --output results.sarif` | GitHub code scanning (Security tab) |
| HTML | `flowsec scan --github --dir . --format html --output report.html` | Shareable report with filtering and PDF export |

JSON and SARIF print to stdout unless `--output` is given, so they pipe cleanly. Exit codes: `0` clean scan, `1` when `--fail-on` triggers, `2` for usage or scan errors.

---

---

## Stack


| Layer | Tools |
|---|---|
| Language | Python 3.11+ |
| YAML Parsing | PyYAML with custom line-tracking loader |
| Terminal Output | rich |
| Machine Output | JSON and SARIF 2.1.0 (GitHub code scanning compatible) |
| HTML Reports | Jinja2 — interactive filtering, expandable findings, PDF export |
| Remote Scanning | PyGithub, python-gitlab, httpx — optional `flowsec[remote]` extra |
| AI Narratives | Anthropic Claude API with local caching — optional `flowsec[ai]` extra |
| Linting | ruff, mypy (strict), bandit |
| Packaging | hatch, pyproject.toml |

---

---

## CLI


```bash
# Scan your whole repo checkout (picks up .github/workflows/)
flowsec scan --github --dir .

# Scan a GitHub Actions repo (remote)
flowsec scan --github --repo owner/repo

# Scan a local GitHub Actions file
flowsec scan --github --file .github/workflows/ci.yml

# JSON to stdout — pipe it anywhere
flowsec scan --github --dir . --format json

# SARIF for GitHub code scanning
flowsec scan --github --dir . --format sarif --output results.sarif

# Scan a GitLab CI file (local)
flowsec scan --gitlab --file .gitlab-ci.yml

# Scan a GitLab CI repo (remote — requires GITLAB_TOKEN)
flowsec scan --gitlab --repo namespace/project

# Scan an Azure DevOps file (local)
flowsec scan --azure --file azure-pipelines.yml

# Scan an Azure DevOps repo (remote — requires AZURE_DEVOPS_TOKEN)
flowsec scan --azure --repo org/project

# Generate an HTML report
flowsec scan --github --repo owner/repo --format html --output report.html

# Generate AI attack narratives (requires ANTHROPIC_API_KEY)
flowsec scan --github --repo owner/repo --ai

# Ignore specific rules
flowsec scan --github --repo owner/repo --ignore FS006 --ignore FS011

# Fail pipeline if findings at or above threshold
flowsec scan --github --repo owner/repo --fail-on critical

# Everything at once
flowsec scan --github --repo owner/repo --ai --output report.html --fail-on high
```

---

---

## Rule Suppression


Suppress specific rules inline with `--ignore`:

```bash
flowsec scan --github --repo owner/repo --ignore FS006 --ignore FS011
```

Or create a `.flowsec.yml` in your repo root for persistent suppression. An entry can optionally be limited to matching files with a glob:

```yaml
ignore:
  - rule_id: FS006
    reason: "We use external timeout management"
  - rule_id: FS002
    file: "legacy/*.yml"
    reason: "Legacy pipelines are being retired, not fixed"
```

---

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
      - uses: actions/checkout@v4
      - name: Install FlowSec
        run: pip install flowsec
      - name: Run FlowSec
        run: flowsec scan --github --dir . --fail-on critical
```

`--fail-on` supports `critical`, `high`, `medium`, and `low` thresholds. Exit codes: `0` clean, `1` threshold hit, `2` usage or scan error.

To get findings into GitHub's Security tab, output SARIF and upload it:

```yaml
      - name: Run FlowSec
        run: flowsec scan --github --dir . --format sarif --output flowsec.sarif
      - name: Upload to code scanning
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: flowsec.sarif
```

---

---

## Status


| Component | Status |
|---|---|
| Rule engine — BaseRule, Finding, Severity | Complete |
| YAML parser with line number tracking | Complete |
| 38 security rules FS001-FS038 | Complete |
| MITRE ATT&CK + OWASP CICD Top 10 mapping | Complete |
| Platform-aware rule engine (GitHub/GitLab/Azure) | Complete |
| GitHub Actions scanner — remote repo and local file | Complete |
| GitLab CI scanner — remote repo and local file | Complete |
| Azure DevOps scanner — remote repo and local file | Complete |
| CLI — `--github/--gitlab/--azure` + `--file/--dir/--repo` | Complete |
| Directory scanning (`--dir` on a repo checkout) | Complete |
| Rich terminal output with risk score (0-100) and line numbers | Complete |
| JSON output (`--format json`) | Complete |
| SARIF 2.1.0 output for GitHub code scanning (`--format sarif`) | Complete |
| HTML report with filtering, PDF export | Complete |
| AI attack narratives with local caching | Complete |
| Pipeline gate `--fail-on` with clean exit codes (0/1/2) | Complete |
| Rule suppression `--ignore` and `.flowsec.yml` (with file globs) | Complete |
| Friendly errors for bad YAML, missing files, failed fetches | Complete |
| Optional-dependency extras (`flowsec[remote]`, `flowsec[ai]`) | Complete |
| GitHub Codespace config | Complete |
| PyPI publish with OIDC trusted publishing | Complete |
| Homebrew tap (`brew install VanshBhardwaj1945/flowsec/flowsec`) | Complete |
| CI: pytest (3.11-3.13), ruff, mypy strict on every push/PR | Complete |
| CI security workflow (gitleaks, bandit, pip-audit, self-scan) | Complete |

---

---

## Roadmap


**Phase 2 — Expansion**
Jenkins support, AWS CodePipeline, 20+ rule library.

---

---

## Security


See [SECURITY.md](SECURITY.md) for the responsible disclosure policy.

---

---

## About this project


Built as a security engineering portfolio project. The goal was to build an actual security tool — not run existing ones — and document every decision along the way.

**[Read the full documentation](docs/FULL_README.md)**
