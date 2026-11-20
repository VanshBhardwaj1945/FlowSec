# What FlowSec catches

All 38 rules, with severity, the MITRE ATT&CK technique and the OWASP CI/CD Top 10 risk each one maps to. Back to the [README](../README.md).

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
