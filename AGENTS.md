# FlowSec — Agent Guide

This document is the authoritative reference for any AI agent working on this codebase. Read it fully before touching anything.

---

## What This Project Is

FlowSec is a static analysis security tool that scans CI/CD pipeline YAML files for attack vectors. It supports three platforms: GitHub Actions, GitLab CI, and Azure DevOps. Every finding maps to a MITRE ATT&CK technique and an OWASP CICD Top 10 category.

It is a real, published Python package on PyPI (`pip install flowsec`) and a Homebrew tap. Changes to core logic affect real users.

**Code style rule for this repo:** keep the code easy for a novice engineer to read. Plain loops over clever one-liners, no metaprogramming, small functions with obvious names, and comments only where the code can't explain itself.

---

## Project Structure

```
FlowSec/
├── src/flowsec/
│   ├── cli.py                  — argparse CLI, Rich display, exit codes, output routing
│   ├── scanner.py              — RULES list, scan_content/scan_file/scan_directory, remote fetchers
│   ├── parser.py               — LineLoader: YAML → dict with __line_<key>__ entries
│   ├── output.py               — to_json() and to_sarif() (SARIF 2.1.0)
│   ├── errors.py               — ScanError: every user-facing failure raises this
│   ├── config.py               — .flowsec.yml ignore entries + apply_ignores/is_ignored
│   ├── report.py               — HTML report via Jinja2 (templates/report.html)
│   ├── ai_narrative.py         — Claude API narratives, cached in ~/.flowsec_cache.json
│   ├── scoring.py              — 0-100 risk score, diminishing returns
│   └── rules/
│       ├── base.py             — BaseRule, Finding, Severity — the contract every rule implements
│       └── <26 rule files>     — FS001-FS026, one class per file
├── tests/
│   ├── fixtures/
│   │   ├── github_all_vulns.yml       — every FS rule fires here
│   │   ├── gitlab_all_vulns.yml       — every applicable rule fires here
│   │   ├── azure_all_vulns.yml        — every applicable rule fires here
│   │   └── sample_workflow_clean.yml  — ZERO rules may fire here (false-positive guard)
│   ├── test_github_rules.py / test_gitlab_rules.py / test_azure_rules.py
│   ├── test_clean_workflow.py  — asserts the clean fixture stays clean
│   ├── test_scanner.py         — error paths, directory scan, ignore config
│   ├── test_cli.py             — exit codes, formats, flags
│   ├── test_output.py          — JSON/SARIF structure
│   └── test_scoring.py         — risk score behavior
├── .github/workflows/
│   ├── ci.yml                  — pytest (3.11-3.13), ruff, mypy strict on push/PR
│   ├── publish.yml             — PyPI publish on v* tags via trusted publishing (OIDC)
│   └── security.yml            — gitleaks, bandit, pip-audit, flowsec self-scan
├── homebrew-tap/Formula/flowsec.rb — canonical formula copy (live tap: VanshBhardwaj1945/homebrew-flowsec)
├── pyproject.toml              — version, deps, extras, ruff/mypy/pytest config
├── PYPI_README.md              — PyPI page (no images)
├── README.md                   — GitHub repo README
├── docs/FULL_README.md         — full documentation
└── SECURITY.md / LICENSE / AGENTS.md
```

---

## How to Run It

Use the project virtualenv: `source .venv/bin/activate` (or call `.venv/bin/flowsec` directly).

```bash
# Local scans
flowsec scan --github --file .github/workflows/ci.yml
flowsec scan --github --dir .              # scans .github/workflows/ in a checkout
flowsec scan --gitlab --file .gitlab-ci.yml
flowsec scan --azure --file azure-pipelines.yml

# Remote scans (need the [remote] extra; GITHUB_TOKEN optional for public repos)
flowsec scan --github --repo owner/repo
flowsec scan --gitlab --repo namespace/project      # needs GITLAB_TOKEN
flowsec scan --azure --repo org/project             # needs AZURE_DEVOPS_TOKEN

# Output formats
flowsec scan --github --dir . --format json                          # stdout
flowsec scan --github --dir . --format sarif --output out.sarif      # GitHub code scanning
flowsec scan --github --dir . --format html --output report.html

# Gate + suppression
flowsec scan --github --dir . --fail-on high --ignore FS006
```

**Exit codes:** `0` clean run, `1` `--fail-on` threshold hit, `2` usage error or scan failure. Keep this contract intact — CI users depend on it.

**Dependencies are split into extras.** The base install is PyYAML + rich + jinja2 + python-dotenv only. PyGithub/python-gitlab/httpx live in `flowsec[remote]`, anthropic in `flowsec[ai]`, and they are imported lazily inside the functions that need them. Never add a top-level import of an extra's package — it would break the base install.

---

## How the Rule Engine Works

### The platform flag is everything

Every rule's `check()` method receives a `platform` argument (`"github"`, `"gitlab"`, or `"azure"`). Rules branch on this to parse the correct YAML structure.

```
--file / --dir / --repo all funnel into scan_content(content, file_path, platform),
which runs every rule in scanner.RULES against the parsed dict.
```

**Never use `--github --file` on a GitLab or Azure YAML.** It will pass `platform="github"` and produce wrong results — most rules will find nothing, and FS003 will fire as a false positive (Azure/GitLab files have no `permissions:` key).

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
```

Rules that only apply to one platform return `[]` immediately:
```python
if platform != "github":
    return []
```

### Two YAML gotchas every rule must respect

1. **PyYAML parses the `on:` trigger key as boolean `True`.** Rules that inspect triggers use `config.get(True, {})`, and rule signatures type the config as `dict[Any, Any]` for this reason. Do not "fix" this to `"on"`.
2. **The parser injects `__line_<key>__` entries** next to every string value for line numbers. When iterating dict keys in rules, always skip keys starting with `__line_`.

### Errors

Everything that can fail in a user-visible way raises `ScanError` (from `flowsec/errors.py`) with a plain-English message. The CLI catches it, prints `Error: ...`, and exits 2. Never let a raw traceback reach the user — if you add a new failure mode, wrap it in `ScanError`.

### Adding a new rule

1. Create `src/flowsec/rules/<name>.py`, inherit from `BaseRule`, implement `check(config, file_path, platform)`.
2. Add the import and an instance to `RULES` in `scanner.py`.
3. Add the vulnerable pattern to the relevant `*_all_vulns.yml` fixture(s) and a test asserting the rule ID fires.
4. Confirm the rule does NOT fire on `tests/fixtures/sample_workflow_clean.yml` — `test_clean_workflow.py` will catch it if it does.
5. Add the rule to the tables in README.md, PYPI_README.md, and docs/FULL_README.md (including the Platforms column).

Next available ID: **FS027**.

---

## Quality Gates — All Must Pass Before Pushing

```bash
pytest                    # full suite with coverage
ruff check src/ tests/    # lint — must be clean
mypy                      # strict mode — must be clean
bandit -r src/ -ll -x src/flowsec/templates/
```

CI runs all of these on every push (`ci.yml`), plus gitleaks / pip-audit / a FlowSec self-scan of `.github/workflows/` (`security.yml`). The self-scan means **any workflow file you add or edit must pass FlowSec itself**: pin actions to full commit SHAs, set `timeout-minutes`, set least-privilege `permissions`, and set `persist-credentials: false` on checkout.

Notes on the lint config:
- Rule files are exempt from E501 — their description/remediation strings are long prose on purpose.
- mypy runs in strict mode over `src/`. New code needs full type annotations.

---

## Git Workflow

Branch protection is active on `main`: no force pushes, required status checks. The repo owner can push directly; contributors go through PRs.

- **Never `git push --force` on main or tags.**
- **Never edit fixture files to remove vulnerabilities** — they are supposed to be vulnerable. The one exception is `sample_workflow_clean.yml`, which must stay clean.
- **Never remove a rule from `RULES`** without removing its import and its tests.
- The `.env` file holds real tokens and is gitignored. Never commit it, never print its contents.

---

## Releasing

### PyPI (automated)

1. Bump `version = "X.Y.Z"` in `pyproject.toml`, commit, push.
2. `git tag vX.Y.Z && git push origin vX.Y.Z`
3. `publish.yml` builds with hatch and publishes via OIDC trusted publishing. No tokens involved. Monitor in the Actions tab.

Never re-tag a version that is already on PyPI — PyPI rejects re-uploads.

Known pin: `hatch==1.14.1` must be installed together with `"virtualenv<21"` in publish.yml (virtualenv 21 removed an API hatch depends on).

### Homebrew (manual, after PyPI publish)

The live tap is `github.com/VanshBhardwaj1945/homebrew-flowsec`; a canonical copy of the formula lives in this repo at `homebrew-tap/Formula/flowsec.rb`.

1. Get the new sdist URL and SHA256 from `https://pypi.org/pypi/flowsec/X.Y.Z/json` → the `urls[]` entry with `packagetype == "sdist"`.
2. Update `url` and `sha256` in the formula. If dependency versions changed, update the matching `resource` blocks.
3. Commit the copy in this repo AND push the same change to the tap repo.
4. Verify: `brew update && brew upgrade VanshBhardwaj1945/flowsec/flowsec` (or `brew audit --new` / `brew test`).

The formula bundles the remote/AI dependencies as resources even though they are optional extras on PyPI — brew users get full functionality out of the box. Keep it that way.

---

## Docs to Keep in Sync

When behavior changes, update all three: `README.md` (GitHub), `PYPI_README.md` (PyPI page — no images), and `docs/FULL_README.md` (deep documentation). The rules tables appear in all three; FULL_README also documents each rule in prose and carries the per-rule platform notes.
