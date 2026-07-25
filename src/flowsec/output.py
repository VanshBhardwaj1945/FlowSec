import json
from importlib.metadata import PackageNotFoundError, version

from .rules.base import Finding
from .scoring import compute_risk_score

try:
    FLOWSEC_VERSION = version("flowsec")
except PackageNotFoundError:
    FLOWSEC_VERSION = "unknown"

SARIF_LEVELS = {
    "critical": "error",
    "high": "error",
    "medium": "warning",
    "low": "note",
}

# GitHub code scanning uses this 0-10 scale to rank alerts.
SECURITY_SEVERITIES = {
    "critical": "9.5",
    "high": "7.5",
    "medium": "5.0",
    "low": "2.5",
}


def count_by_severity(findings: list[Finding]) -> dict[str, int]:
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for finding in findings:
        counts[finding.severity.value] += 1
    return counts


def to_json(findings: list[Finding], target: str) -> str:
    results = []
    for finding in findings:
        results.append(
            {
                "rule_id": finding.rule_id,
                "title": finding.title,
                "severity": finding.severity.value,
                "description": finding.description,
                "remediation": finding.remediation,
                "mitre_technique": finding.mitre_technique,
                "owasp_category": finding.owasp_category,
                "file": finding.file_path,
                "line": finding.line_number,
                "narrative": finding.narrative,
            }
        )

    report = {
        "tool": "flowsec",
        "version": FLOWSEC_VERSION,
        "target": target,
        "risk_score": compute_risk_score(findings),
        "summary": count_by_severity(findings),
        "findings": results,
    }
    return json.dumps(report, indent=2)


def to_sarif(findings: list[Finding]) -> str:
    rules = []
    seen_rule_ids = set()
    for finding in findings:
        if finding.rule_id in seen_rule_ids:
            continue
        seen_rule_ids.add(finding.rule_id)
        rules.append(
            {
                "id": finding.rule_id,
                "name": finding.title,
                "shortDescription": {"text": finding.title},
                "defaultConfiguration": {"level": SARIF_LEVELS[finding.severity.value]},
                "properties": {
                    "security-severity": SECURITY_SEVERITIES[finding.severity.value],
                    "mitre_technique": finding.mitre_technique,
                    "owasp_category": finding.owasp_category,
                    "tags": ["security"],
                },
            }
        )

    results = []
    for finding in findings:
        results.append(
            {
                "ruleId": finding.rule_id,
                "level": SARIF_LEVELS[finding.severity.value],
                "message": {"text": f"{finding.description} Remediation: {finding.remediation}"},
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {"uri": finding.file_path},
                            "region": {"startLine": max(finding.line_number, 1)},
                        }
                    }
                ],
            }
        )

    sarif = {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "FlowSec",
                        "informationUri": "https://github.com/VanshBhardwaj1945/FlowSec",
                        "version": FLOWSEC_VERSION,
                        "rules": rules,
                    }
                },
                "results": results,
            }
        ],
    }
    return json.dumps(sarif, indent=2)
