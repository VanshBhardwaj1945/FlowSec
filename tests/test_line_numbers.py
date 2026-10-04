"""Every finding cites the exact line of what triggered it.

Each rule fires somewhere in the *_all_vulns fixtures; for every finding we read
the cited line back out of the file and check it holds that rule's evidence.
"""

import json
import re
from pathlib import Path

import pytest

from flowsec.output import to_sarif
from flowsec.scanner import RULES, scan_content, scan_file

FIXTURES = Path(__file__).parent / "fixtures"
ALL_VULNS = [
    ("github_all_vulns.yml", "github"),
    ("sample_workflow_vulnerable.yml", "github"),
    ("gitlab_all_vulns.yml", "gitlab"),
    ("azure_all_vulns.yml", "azure"),
]

JOB_HEADER = r"^(-\s*job:\s*\S+|[\w-]+:)$"

# What the cited line must contain for each rule.
EVIDENCE = {
    "FS001": r"(KEY|PASSWORD|TOKEN|SECRET)\w*\s*:",
    "FS002": r"uses:",
    "FS003": r"permissions",
    "FS004": r"uses:\s*(aws-actions|azure/login|google-github-actions)",
    "FS005": r"actions/checkout",
    "FS006": JOB_HEADER,
    "FS007": r"(runs-on|tags|name):",
    "FS008": r"uses:",
    "FS009": r"(pip3? install|npm (install|i)\b|yarn add)",
    "FS010": r"(?i)(password=|token=|api_key=|secret=|authorization)",
    "FS011": r"\$\{\{.*github\.",
    "FS012": JOB_HEADER,
    "FS013": r"inputs\.",
    "FS014": r"image:|docker://",
    "FS015": r"actions/checkout|persist-credentials",
    "FS016": r"workflow_run",
    "FS017": r"continue-on-error|allow_failure|continueOnError",
    "FS018": r"--[\w-]+\s+\$",
    "FS019": r"curl|wget",
    "FS020": r"docker run",
    "FS021": r"--build-arg",
    "FS022": r"(path|PathtoPublish|targetPath)\s*:|^-\s",
    "FS023": r"curl (-k|--insecure)",
    "FS024": r"--privileged|--cap-add|seccomp",
    "FS025": r"printenv|\benv\b|echo \$",
    "FS026": JOB_HEADER,
    "FS027": r"docker\.sock",
    "FS028": r"://[^/\s:@]+:[^/\s@]+@",
    "FS029": r"\$\{\{.*github\.",
    "FS030": r"secrets:\s*inherit",
    "FS031": r"actions/cache",
    "FS032": r"(remote|ref|project):|https?://",
    "FS033": r"ACTIONS_ALLOW_UNSECURE_COMMANDS",
    "FS034": r"http://",
    "FS035": r"GITHUB_(ENV|PATH)",
    "FS036": r"persistCredentials",
    "FS037": r"base64",
    "FS038": r"dind",
}


def _findings_with_text() -> list[tuple[str, int, str]]:
    rows = []
    for name, platform in ALL_VULNS:
        path = FIXTURES / name
        lines = path.read_text().split("\n")
        for finding in scan_file(str(path), platform):
            text = lines[finding.line_number - 1].strip() if finding.line_number > 0 else ""
            rows.append((finding.rule_id, finding.line_number, text))
    return rows


def test_every_rule_has_evidence_pattern() -> None:
    assert {rule.rule_id for rule in RULES} == set(EVIDENCE)


def test_every_rule_is_exercised_by_a_fixture() -> None:
    fired = {rule_id for rule_id, _, _ in _findings_with_text()}
    assert fired == set(EVIDENCE)


@pytest.mark.parametrize(("rule_id", "line", "text"), _findings_with_text())
def test_finding_cites_its_exact_line(rule_id: str, line: int, text: str) -> None:
    assert line > 0, f"{rule_id} reported no line"
    assert re.search(EVIDENCE[rule_id], text), f"{rule_id} cited line {line}: {text!r}"


def test_run_block_maps_to_the_script_line() -> None:
    workflow = (
        "on: push\n"
        "permissions:\n"
        "  contents: read\n"
        "jobs:\n"
        "  build:\n"
        "    runs-on: ubuntu-latest\n"
        "    timeout-minutes: 5\n"
        "    steps:\n"
        "      - run: |\n"
        "          echo starting\n"
        "          echo still fine\n"
        "          curl -k https://example.com\n"
    )
    findings = [f for f in scan_content(workflow, "wf.yml", "github") if f.rule_id == "FS023"]
    assert [f.line_number for f in findings] == [12]


def test_sarif_region_carries_the_line() -> None:
    path = FIXTURES / "github_all_vulns.yml"
    findings = scan_file(str(path), "github")
    sarif = json.loads(to_sarif(findings))
    lines = [r["locations"][0]["physicalLocation"]["region"]["startLine"] for r in sarif["runs"][0]["results"]]
    assert lines == [f.line_number for f in findings]
    assert all(line > 1 for line in lines)


def test_azure_script_steps_are_scanned_with_lines() -> None:
    pipeline = (
        "trigger: none\n"
        "stages:\n"
        "- stage: build\n"
        "  jobs:\n"
        "  - job: build\n"
        "    timeoutInMinutes: 5\n"
        "    steps:\n"
        "    - script: |\n"
        "        echo starting\n"
        "        curl -k https://example.com\n"
        "    - bash: docker run --privileged img\n"
        "    - powershell: Invoke-WebRequest http://example.com/x.ps1\n"
    )
    found = {(f.rule_id, f.line_number) for f in scan_content(pipeline, "azure-pipelines.yml", "azure")}
    assert ("FS023", 10) in found
    assert ("FS024", 11) in found


def test_gitlab_before_and_after_script_are_scanned() -> None:
    pipeline = (
        "build:\n"
        "  timeout: 10m\n"
        "  before_script:\n"
        "    - curl -k https://example.com\n"
        "  script:\n"
        "    - make\n"
        "  after_script:\n"
        "    - printenv\n"
    )
    found = {(f.rule_id, f.line_number) for f in scan_content(pipeline, ".gitlab-ci.yml", "gitlab")}
    assert ("FS023", 4) in found
    assert ("FS025", 8) in found
