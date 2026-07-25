import json
from pathlib import Path

from flowsec.output import to_json, to_sarif
from flowsec.scanner import scan_file

FIXTURE = str(Path(__file__).parent / "fixtures" / "github_all_vulns.yml")


def get_findings():
    return scan_file(FIXTURE)


def test_json_output_is_valid_and_complete():
    findings = get_findings()
    report = json.loads(to_json(findings, FIXTURE))

    assert report["tool"] == "flowsec"
    assert report["target"] == FIXTURE
    assert 0 <= report["risk_score"] <= 100
    assert len(report["findings"]) == len(findings)
    assert sum(report["summary"].values()) == len(findings)

    first = report["findings"][0]
    for key in ("rule_id", "title", "severity", "description", "remediation", "file", "line"):
        assert key in first


def test_json_output_with_no_findings():
    report = json.loads(to_json([], "empty.yml"))
    assert report["findings"] == []
    assert report["risk_score"] == 0


def test_sarif_output_structure():
    findings = get_findings()
    sarif = json.loads(to_sarif(findings))

    assert sarif["version"] == "2.1.0"
    run = sarif["runs"][0]
    assert run["tool"]["driver"]["name"] == "FlowSec"
    assert len(run["results"]) == len(findings)

    result = run["results"][0]
    assert result["level"] in ("error", "warning", "note")
    assert result["locations"][0]["physicalLocation"]["region"]["startLine"] >= 1


def test_sarif_rules_are_deduplicated():
    findings = get_findings()
    rules = json.loads(to_sarif(findings))["runs"][0]["tool"]["driver"]["rules"]
    rule_ids = [r["id"] for r in rules]
    assert len(rule_ids) == len(set(rule_ids))


def test_sarif_severity_mapping():
    findings = get_findings()
    sarif = json.loads(to_sarif(findings))
    by_rule = {r["ruleId"]: r["level"] for r in sarif["runs"][0]["results"]}
    # FS001 (hardcoded secret) is critical -> error; FS006 (missing timeout) is low -> note
    assert by_rule["FS001"] == "error"
    assert by_rule["FS006"] == "note"
