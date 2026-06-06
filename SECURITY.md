# Security Policy

## Supported Versions

| Version | Supported |
| ------- | --------- |
| 0.5.x   | Yes       |
| < 0.5   | No        |

## Reporting a Vulnerability

**Do not open a public GitHub issue for security vulnerabilities.**

Report vulnerabilities via [GitHub Security Advisories](https://github.com/VanshBhardwaj1945/FlowSec/security/advisories/new) or email **Scorpio.vansh@gmail.com** with subject `[SECURITY] FlowSec`.

Include:
- A description of the vulnerability and its impact
- Steps to reproduce or a proof-of-concept
- Any suggested fix (optional)

You will receive a response within **72 hours** and a fix or mitigation within **14 days** for confirmed issues.

## Scope

**In scope:**
- Remote code execution via malicious pipeline YAML
- Secret or token leakage from the tool itself
- Path traversal when scanning local files
- SSRF via remote repo scanning (GitHub/GitLab/Azure)
- Dependency vulnerabilities with a realistic attack path

**Out of scope:**
- Vulnerabilities in the pipeline files FlowSec *reports on* (those are the findings, not bugs in FlowSec)
- Issues that require physical access to the user's machine
- Social engineering

## Security Design

- Tokens (`GITHUB_TOKEN`, `GITLAB_TOKEN`, `AZURE_DEVOPS_TOKEN`, `ANTHROPIC_API_KEY`) are loaded from environment variables / `.env` only — never passed as CLI arguments
- YAML is parsed with a subclass of `yaml.SafeLoader` — arbitrary code execution via YAML is not possible
- HTML reports use Jinja2 with `autoescape=select_autoescape(["html"])` — XSS from finding content is prevented
- Remote HTTP requests use explicit timeouts to prevent connection hangs
- All GitHub Actions in this repo's workflows are pinned to commit SHAs
