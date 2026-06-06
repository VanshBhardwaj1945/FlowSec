# FlowSec — Agent Guide

This document is the authoritative reference for any AI agent working on this codebase. Read it fully before touching anything.

---

## What This Project Is

FlowSec is a static analysis security tool that scans CI/CD pipeline YAML files for attack vectors. It supports three platforms: GitHub Actions, GitLab CI, and Azure DevOps. Every finding maps to a MITRE ATT&CK technique and an OWASP CICD Top 10 category.

It is a real, published Python package on PyPI (`pip install flowsec`). Changes to core logic affect real users.

---

## Project Structure

```
FlowSec/
├── src/pipelineguard/
│   ├── cli.py                  # Entry point — argument parsing, display logic
│   ├── scanner.py              # scan_file / scan_gitlab_file / scan_azure_file / scan_repo
│   ├── parser.py               # YAML loader with line number tracking
│   ├── config.py               # Loads .flowsec.yml ignore rules
│   ├── report.py               # HTML report generation (Jinja2)
│   ├── ai_narrative.py         # Claude API integration for attack narratives
│   ├── scoring.py              # Risk score calculation
│   └── rules/
│       ├── base.py             # BaseRule, Finding, Severity — the contract every rule implements
│       ├── hardcoded_secrets.py        # FS001
│       ├── unpinned_actions.py         # FS002
│       ├── excessive_permissions.py    # FS003
│       ├── missing_oidc.py             # FS004
│       ├── pull_request_target.py      # FS005
│       ├── missing_timeout.py          # FS006
│       ├── self_hosted_runner.py       # FS007
│       ├── artifact_signing.py         # FS008
│       ├── dependency_pinning.py       # FS009
│       ├── secrets_in_run.py           # FS010
│       ├── github_context_injection.py # FS011
│       ├── missing_env_protection.py   # FS012
│       ├── workflow_dispatch_injection.py # FS013
│       ├── mutable_container_image.py  # FS014
│       ├── persist_credentials.py      # FS015
│       ├── workflow_run_trigger.py     # FS016
│       ├── continue_on_error_security.py # FS017
│       ├── secret_as_cli_arg.py        # FS018
│       ├── unverified_install_script.py # FS019
│       ├── container_runs_as_root.py   # FS020
│       ├── secrets_in_build_args.py    # FS021
│       ├── broad_artifact_upload.py    # FS022
│       ├── insecure_curl.py            # FS023
│       ├── privileged_docker.py        # FS024
│       ├── env_vars_in_logs.py         # FS025
│       └── deploy_all_branches.py      # FS026
├── tests/
│   ├── fixtures/
│   │   ├── github_all_vulns.yml    # GitHub Actions fixture — every FS rule should fire
│   │   ├── gitlab_all_vulns.yml    # GitLab CI fixture — every applicable rule should fire
│   │   └── azure_all_vulns.yml     # Azure DevOps fixture — every applicable rule should fire
│   ├── test_github_rules.py
│   ├── test_gitlab_rules.py
│   └── test_azure_rules.py
├── .github/workflows/
│   └── publish.yml             # Publishes to PyPI on v* tags via trusted publishing (OIDC)
├── pyproject.toml              # Version, dependencies, hatch build config
├── AGENTS.md                   # This file
└── README.md                   # PyPI-facing documentation
```

---

## How to Run It

The project uses a virtual environment at `.venv/`. Always use `.venv/bin/flowsec`, not a system `flowsec`.

```bash
# GitHub Actions — local file
.venv/bin/flowsec scan --file .github/workflows/ci.yml

# GitHub Actions — remote repo (requires GITHUB_TOKEN in .env)
.venv/bin/flowsec scan --repo owner/repo

# GitLab CI
.venv/bin/flowsec scan --gitlab .gitlab-ci.yml

# Azure DevOps
.venv/bin/flowsec scan --azure azure-pipelines.yml

# With HTML report
.venv/bin/flowsec scan --file workflow.yml --output report.html

# With AI narratives (requires ANTHROPIC_API_KEY in .env)
.venv/bin/flowsec scan --file workflow.yml --ai

# Fail on severity threshold (for use in CI)
.venv/bin/flowsec scan --file workflow.yml --fail-on critical

# Suppress specific rules
.venv/bin/flowsec scan --file workflow.yml --ignore FS006 --ignore FS003
```

To validate that everything is working, run against the three fixture files:

```bash
.venv/bin/flowsec scan --file tests/fixtures/github_all_vulns.yml
.venv/bin/flowsec scan --gitlab tests/fixtures/gitlab_all_vulns.yml
.venv/bin/flowsec scan --azure tests/fixtures/azure_all_vulns.yml
```

Expected output: GitHub ~36 findings, GitLab ~29 findings, Azure ~24 findings.

---

## How the Rule Engine Works

### The platform flag is everything

Every rule's `check()` method receives a `platform` argument (`"github"`, `"gitlab"`, or `"azure"`). Rules branch on this to parse the correct YAML structure. This is the most critical thing to understand.

```
--file      → scan_file()       → platform="github"   (GitHub Actions YAML only)
--gitlab    → scan_gitlab_file() → platform="gitlab"
--azure     → scan_azure_file()  → platform="azure"
--repo      → scan_repo()        → platform="github"   (fetches from GitHub API)
```

**Never use `--file` on a GitLab or Azure YAML.** It defaults to `platform="github"` and will produce wrong results — most rules will find nothing, and FS003 will fire as a false positive (because Azure/GitLab files have no `permissions:` key).

### YAML structure per platform

GitHub Actions:
```yaml
jobs:
  build:
    steps:
      - run: pip install ...
        env:
          SECRET: hardcoded
```

GitLab CI — top-level job keys with `script:` arrays:
```yaml
build:
  script:
    - pip install ...
  variables:
    SECRET: hardcoded
```

Azure DevOps — `jobs:` list for job-level checks, top-level keys with `script:` for script checks:
```yaml
jobs:
  - job: build
    steps:
      - script: echo hi

build-scripts:
  script:
    - pip install ...
```

Rules that only apply to one platform return `[]` immediately:
```python
if platform != "github":
    return []
```

Rules that support multiple platforms branch with `if/elif`:
```python
if platform == "github":
    # parse jobs[].steps[].run
elif platform in ("gitlab", "azure"):
    # iterate top-level keys, look for script: arrays
```

### The parser

`parse_pipeline_with_lines(content)` returns a standard Python dict. It uses a custom `LineLoader` that injects `__line_{key}__` entries alongside every string value so rules can report accurate line numbers. When iterating dict keys in rules, always skip keys that start with `__line_`.

### The Finding dataclass

```python
@dataclass
class Finding:
    rule_id: str          # e.g. "FS001"
    title: str
    severity: Severity    # Severity.CRITICAL / HIGH / MEDIUM / LOW
    description: str      # specific to the finding instance
    remediation: str
    mitre_technique: str  # e.g. "T1552.001"
    file_path: str
    line_number: int = 0
    narrative: str = ""   # populated only with --ai flag
    owasp_category: str = ""  # e.g. "CICD-SEC-6"
```

### Adding a new rule

1. Create `src/pipelineguard/rules/fsXXX_name.py` following the pattern of any existing rule.
2. Implement `BaseRule` with `rule_id`, `title`, `severity`, and a `check()` method.
3. Import and instantiate it in `scanner.py` — add it to the `RULES` list.
4. Add the vulnerability pattern to each relevant fixture file (`github_all_vulns.yml`, `gitlab_all_vulns.yml`, `azure_all_vulns.yml`).
5. Add a test assertion in each relevant `test_*_rules.py`.
6. Add it to the rule table in `README.md`.

Rule IDs are sequential. The next available ID is FS027.

---

## Testing

Tests use pytest. Run from the project root with the venv active:

```bash
.venv/bin/python -m pytest tests/ -v
```

Each test file has:
- Individual tests per rule asserting the rule ID appears in the scan results
- A `test_all_*_rules_detected` test that asserts the full expected set fires

The fixtures are intentionally full of every vulnerability pattern. Do not "fix" them — they are meant to be vulnerable.

---

## Safeguards — Read Before Making Changes

### Never mix platform flags with the wrong YAML format
`--file` is GitHub Actions only. `--gitlab` is GitLab CI only. `--azure` is Azure DevOps only. Running the wrong flag against the wrong file produces misleading results silently — it won't error, it'll just miss everything or fire false positives.

### Never edit the fixture files to remove vulnerabilities
`tests/fixtures/github_all_vulns.yml`, `gitlab_all_vulns.yml`, and `azure_all_vulns.yml` are test inputs. They are supposed to contain every vulnerability pattern. Cleaning them up will cause tests to fail.

### Never remove a rule from the RULES list in scanner.py without also removing its import and test
The list in `scanner.py` is the single source of truth for which rules run. If a rule is not in this list, it will never execute regardless of whether the file exists.

### Never bump the version without tagging
The publish workflow in `.github/workflows/publish.yml` triggers only on `v*` tags. A version bump in `pyproject.toml` alone does nothing — you must also create and push a git tag matching the version (e.g. `git tag v0.5.0 && git push origin v0.5.0`).

### Never create a tag for a version already on PyPI
PyPI rejects duplicate versions. Check the existing tags with `git tag -l` before creating one. If a tag already exists locally and you need to retag a different commit, that requires deleting and recreating — confirm with the user first.

### Do not use --force push on main
The main branch has the PyPI publish workflow connected to it. Force pushes can corrupt the tag/commit relationship that the publish workflow depends on.

### The .env file is not committed
`GITHUB_TOKEN` and `ANTHROPIC_API_KEY` live in `.env` (loaded via `python-dotenv`). Never commit this file. The `--repo` and `--ai` flags will silently fail or error without these set.

### FS003 is GitHub-only by design
FS003 (Excessive Permissions) fires when a GitHub workflow has `permissions: write-all` or no `permissions` key at all (which defaults to broad access). It returns `[]` for GitLab and Azure. If you see FS003 appearing on a GitLab or Azure scan, the wrong platform flag was used.

---

## Publishing to PyPI

The project uses PyPI trusted publishing (OIDC) — no API token needed. The workflow in `.github/workflows/publish.yml` handles everything automatically when a `v*` tag is pushed.

Steps to release a new version:
1. Update `version = "X.Y.Z"` in `pyproject.toml`
2. Commit: `git commit -m "bump version to X.Y.Z"`
3. Push: `git push origin main`
4. Tag and push: `git tag vX.Y.Z && git push origin vX.Y.Z`

The GitHub Actions workflow will build with `hatch build` and publish automatically. Monitor it in the Actions tab.

The README.md is used as the PyPI long description. Hatchling detects `text/markdown` from the `.md` extension automatically — no extra config needed.

---

## Key Files to Know

| File | Why it matters |
|---|---|
| `src/pipelineguard/scanner.py` | The `RULES` list controls which rules run. Every new rule must be added here. |
| `src/pipelineguard/rules/base.py` | The `BaseRule`, `Finding`, and `Severity` contracts. All rules inherit from here. |
| `src/pipelineguard/cli.py` | Maps CLI flags to scanner functions. The `platform` value is set here. |
| `src/pipelineguard/parser.py` | The YAML loader. Produces the `config` dict every rule receives. |
| `pyproject.toml` | Version number and build config. |
| `tests/fixtures/` | The ground truth for what each platform's YAML looks like and what should be detected. |
