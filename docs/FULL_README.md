# FlowSec — Full Documentation


## What is this project?

FlowSec is a Python command line security tool that scans CI/CD pipeline configurations for attack vectors. It connects to the GitHub API, pulls every workflow YAML file from a target repository, runs a library of security rules against them, and outputs a prioritized list of findings with a risk score.

Every finding maps to a MITRE ATT&CK technique. Every rule has a documented attack narrative explaining exactly how the misconfiguration gets exploited in the real world.

The rule engine is pluggable — adding a new rule is one new file. Nothing else in the codebase changes.

---

## Contents

- [What is this project?](#what-is-this-project)
- [Why pipelines are an attack surface](#why-pipelines-are-an-attack-surface)
- [Stack](#stack)
- [Project Structure](#project-structure)
- [Rule Engine](#rule-engine)
- [Rules](#rules)
- [Parser](#parser)
- [Issues Resolved](#issues-resolved)

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
| jsonpath-ng | Queries deeply nested YAML structures in rules |
| rich | Colored terminal output — findings tables, progress bars |
| anthropic | Claude API — generates attack narratives per finding |
| jinja2 | HTML report templating |
| Pygments | Syntax highlighting in HTML report |
| python-dotenv | Loads API credentials from .env locally |
| pytest | Test suite |
| pytest-mock | Mocks GitHub and GitLab API responses in tests |
| pytest-cov | Coverage reporting — target 90%+ on all rules |
| ruff | Linting and formatting |
| mypy | Type checking — all functions typed from day one |
| bandit | Scans FlowSec's own Python code for security issues |
| hatch | Build and PyPI publishing |
| Docker | Multi-stage container packaging |

---

## Project Structure

```
FlowSec/
├── src/
│   └── pipelineguard/
│       ├── __init__.py
│       ├── cli.py               — argparse CLI entry point
│       ├── scanner.py           — GitHub API connection and orchestration
│       ├── parser.py            — YAML to Python dict conversion
│       ├── scoring.py           — risk score aggregation
│       ├── report.py            — HTML report generation via Jinja2
│       ├── ai_narrative.py      — Claude API integration for attack narratives
│       └── rules/
│           ├── base.py          — BaseRule ABC, Finding dataclass, Severity enum
│           ├── hardcoded_secrets.py
│           ├── unpinned_actions.py
│           ├── excessive_permissions.py
│           ├── missing_oidc.py
│           ├── pull_request_target.py
│           ├── missing_timeout.py
│           ├── self_hosted_runner.py
│           └── artifact_signing.py
├── tests/
│   ├── fixtures/
│   │   ├── sample_workflow_clean.yml
│   │   └── sample_workflow_vulnerable.yml
│   ├── conftest.py
│   └── test_*.py
├── docs/
│   └── screenshots/
├── pyproject.toml
├── Makefile
├── Dockerfile
└── docker-compose.yml
```

---

## Rule Engine

The rule engine is built around three components in `src/pipelineguard/rules/base.py`.

**Severity**
An enum with four levels — CRITICAL, HIGH, MEDIUM, LOW. An enum is used instead of plain strings so a typo like `"criitcal"` throws an error immediately rather than silently producing a broken report.

**Finding**
A dataclass that every rule returns when it detects a problem. Every finding has the same shape regardless of which rule produced it — rule ID, title, severity, description, remediation steps, MITRE technique, file path, and line number. The report generator always knows exactly what fields to expect.

**BaseRule**
An abstract base class every rule inherits from. It enforces that every rule must implement a `check()` method. If a new rule is written without `check()`, Python throws an error at import time — not silently at runtime when the scanner tries to call it.

`check()` takes the parsed config dictionary and the file path, and returns a list of `Finding` objects. A list because a single file can have multiple instances of the same problem — five hardcoded secrets in one workflow file should produce five findings, not one.

---

## Rules

**FS001 — Hardcoded Secrets**
MITRE T1552.001 — Credentials in Files

Scans every environment variable across every job and step for suspicious variable names — API_KEY, PASSWORD, TOKEN, SECRET, PRIVATE_KEY, and others. If the variable name matches a suspicious pattern and the value does not reference GitHub Secrets via `${{ secrets.NAME }}`, it is flagged as a hardcoded credential.

The distinction is simple. `${{` means the value is being pulled from a secret manager at runtime — safe. Anything else is a plaintext credential sitting in a file committed to git — flagged.

**FS002 — Unpinned Actions**
MITRE T1195.001 — Supply Chain Compromise

Scans every `uses` field across all jobs and steps. An action is considered safely pinned only if it references a full 40 character git commit hash. Branch references like `@main` or `@master` and version tags like `@v3` are both flagged.

Version tags are flagged because a repo owner can delete and recreate a tag pointing to entirely different code. A commit hash is immutable. `@main` means "whatever code is on main right now" — if that repo gets compromised and malicious code gets pushed, your pipeline pulls and executes it automatically on the next build.

This is the GitHub Actions equivalent of a supply chain attack. The SolarWinds breach followed the same pattern at a larger scale — malicious code injected into a trusted dependency that gets pulled automatically by downstream consumers.

---

## Parser

`src/pipelineguard/parser.py` has one job — take a file path, read the YAML file, return a Python dictionary.

`yaml.safe_load` is used instead of `yaml.load`. The difference is that `safe_load` refuses to execute any code that might be embedded in the YAML. Using `yaml.load` on untrusted pipeline configs could result in code execution during parsing.

Known quirk — PyYAML converts the YAML key `on` to the Python boolean `True` because `on` is a reserved word in YAML. This does not affect any rules since none of them inspect the trigger block.

---

## Issues Resolved

| Issue | Resolution |
|---|---|
| PyYAML converts `on` key to Python `True` | Known PyYAML behavior — does not affect rule accuracy |
| pip install blocked by macOS system Python | Created virtual environment with `python3 -m venv`, installed inside it |
| venv created at wrong path | Ran example command literally — created at `path/to/venv` instead of `.venv`, added `path/` to `.gitignore` |