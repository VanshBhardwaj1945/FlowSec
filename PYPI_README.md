# FlowSec

A Python command-line security tool that scans CI/CD pipeline configurations for attack vectors across **GitHub Actions**, **GitLab CI**, and **Azure DevOps**. Every finding maps to a MITRE ATT&CK technique and an OWASP CICD Top 10 category.

The pipeline is the attack surface. FlowSec treats it that way.

---

## Install

```bash
pip install flowsec
```

---

## Quick Start

```bash
# Scan a GitHub Actions repo
export GITHUB_TOKEN=your_token
flowsec scan --github --repo owner/repo

# Scan a local GitHub Actions workflow file
flowsec scan --github --file .github/workflows/ci.yml

# Scan a GitLab CI file
flowsec scan --gitlab --file .gitlab-ci.yml

# Scan an Azure DevOps pipeline file
flowsec scan --azure --file azure-pipelines.yml

# Generate an HTML report
flowsec scan --github --repo owner/repo --output report.html

# Generate AI attack narratives (requires ANTHROPIC_API_KEY)
flowsec scan --github --repo owner/repo --ai

# Fail pipeline if findings at or above threshold
flowsec scan --github --repo owner/repo --fail-on critical

# Ignore specific rules
flowsec scan --github --repo owner/repo --ignore FS006 --ignore FS011
```

---

## Platforms and Tokens

| Platform | File scan | Remote scan | Token required |
|---|---|---|---|
| GitHub Actions | `--github --file` | `--github --repo owner/repo` | `GITHUB_TOKEN` (remote only) |
| GitLab CI | `--gitlab --file` | `--gitlab --repo namespace/project` | `GITLAB_TOKEN` (remote only) |
| Azure DevOps | `--azure --file` | `--azure --repo org/project` | `AZURE_DEVOPS_TOKEN` (always — Azure requires auth even for public projects) |

Set tokens in a `.env` file in your working directory or as environment variables. FlowSec loads `.env` automatically.

---

## 26 Security Rules

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
| FS011 | GitHub Context Injection — Untrusted Event Data in Run Step | CRITICAL | T1059.004 | CICD-SEC-4 |
| FS012 | Missing Environment Protection — Deploy Job Has No Approval Gate | HIGH | T1078 | CICD-SEC-5 |
| FS013 | Workflow Dispatch Injection — Unvalidated Input in Shell Command | CRITICAL | T1059 | CICD-SEC-9 |
| FS014 | Mutable Container Image — Unpinned Image Tag in Pipeline | MEDIUM | T1195.001 | CICD-SEC-3 |
| FS015 | Persist Credentials — GitHub Token Remains in Git Config After Checkout | MEDIUM | T1552.001 | CICD-SEC-6 |
| FS016 | workflow_run Trigger — Privileged Execution from Untrusted Workflow | HIGH | T1059 | CICD-SEC-1 |
| FS017 | Security Scan Silenced — Failures Suppressed with continue-on-error | MEDIUM | T1562.001 | CICD-SEC-7 |
| FS018 | Secret as CLI Argument — Credential Exposed in Process List | HIGH | T1552 | CICD-SEC-6 |
| FS019 | Unverified Install Script — Remote Code Fetched and Executed Directly | HIGH | T1195.002 | CICD-SEC-3 |
| FS020 | Container Running as Root — Elevated Privilege in Pipeline | HIGH | T1611 | CICD-SEC-7 |
| FS021 | Secret in Docker Build Argument — Credential Stored in Image History | HIGH | T1552.001 | CICD-SEC-6 |
| FS022 | Broad Artifact Upload — Entire Workspace Exposed as Artifact | MEDIUM | T1560 | CICD-SEC-9 |
| FS023 | Insecure curl — SSL Verification Disabled in Pipeline | HIGH | T1071 | CICD-SEC-3 |
| FS024 | Privileged Docker Container — Full Host Access Granted in Pipeline | CRITICAL | T1611 | CICD-SEC-7 |
| FS025 | Environment Variables Printed to Logs — Secrets Exposed in Pipeline Output | MEDIUM | T1552.001 | CICD-SEC-6 |
| FS026 | Unguarded Deploy — Deployment Job Runs on Untrusted Branches | HIGH | T1078 | CICD-SEC-1 |

---

## Risk Score

Every scan produces a 0-100 risk score using severity-weighted diminishing returns and exponential normalization. A single critical finding scores ~28. A heavily vulnerable pipeline scores ~90-97. The score cannot exceed 100.

---

## Rule Suppression

```bash
# CLI flag
flowsec scan --github --repo owner/repo --ignore FS006 --ignore FS011

# .flowsec.yml in your repo root
```

```yaml
ignore:
  - rule_id: FS006
    reason: "We use external timeout management"
  - rule_id: FS011
    reason: "Branch protection managed at org level"
```

---

## Use as a Pipeline Gate

```yaml
name: FlowSec Security Scan
on: [push, pull_request]
jobs:
  security:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - run: pip install flowsec
      - run: flowsec scan --github --file .github/workflows/ci.yml --fail-on critical
```

---

## Security

FlowSec is built to the same standard it enforces:

- All GitHub Actions pinned to commit SHAs with least-privilege permissions
- PyPI publishing via OIDC trusted publishing — no long-lived tokens
- Own CI runs gitleaks, bandit, pip-audit, and FlowSec self-scan on every push
- Branch protection on main — force push blocked, 4 required status checks
- YAML parsed with a SafeLoader subclass — no code execution risk
- HTML reports use Jinja2 autoescape — XSS from finding content prevented

Report vulnerabilities via GitHub Security Advisories or email Scorpio.vansh@gmail.com.

---

## License

MIT — see LICENSE on GitHub.

**Source:** https://github.com/VanshBhardwaj1945/FlowSec
