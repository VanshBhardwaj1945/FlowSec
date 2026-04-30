# FlowSec

> A Python security tool that scans CI/CD pipeline configurations for attack vectors across GitHub Actions, GitLab CI, and Azure DevOps. Every finding maps to a MITRE ATT&CK technique and OWASP CICD Top 10 category.
>
> The pipeline is the attack surface. FlowSec treats it that way.

[![PyPI version](https://badge.fury.io/py/flowsec.svg)](https://badge.fury.io/py/flowsec)


[![Open in GitHub Codespaces](https://github.com/codespaces/badge.svg)](https://codespaces.new/VanshBhardwaj1945/FlowSec)

**[Full documentation](docs/FULL_README.md)**

**Install from PyPI:**
```bash
pip install flowsec
flowsec scan --repo owner/repo
```

**Or run from source:**
```bash
git clone https://github.com/VanshBhardwaj1945/FlowSec.git
cd FlowSec
python3 -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
cp .env.example .env
# Add your GITHUB_TOKEN to .env

flowsec scan --repo owner/repo
flowsec scan --file .github/workflows/ci.yml
flowsec scan --gitlab .gitlab-ci.yml
flowsec scan --azure azure-pipelines.yml
flowsec scan --repo owner/repo --ai --output report.html
```


## Status

| Component | Status |
|---|---|
| Rule engine — BaseRule, Finding, Severity | Complete |
| YAML parser with line number tracking | Complete |
| 13 security rules FS001-FS013 | Complete |
| MITRE ATT&CK + OWASP CICD Top 10 mapping | Complete |
| Platform-aware rule engine | Complete |
| GitHub Actions scanner — API and local file | Complete |
| GitLab CI scanner | Complete |
| Azure DevOps scanner | Complete |
| CLI — all flags | Complete |
| Rich terminal output with risk score | Complete |
| HTML report with filtering, PDF export | Complete |
| AI attack narratives with local caching | Complete |
| Line number tracking | Complete |
| Pipeline gate --fail-on | Complete |
| GitHub Codespace config | Complete |
| PyPI publish | Complete |
