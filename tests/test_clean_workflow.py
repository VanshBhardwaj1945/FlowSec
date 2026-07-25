"""
False-positive guard: a well-configured workflow must produce zero findings.
If a rule starts firing here, it regressed and would flag clean pipelines.
"""

from pathlib import Path

from flowsec.scanner import scan_file

FIXTURE = str(Path(__file__).parent / "fixtures" / "sample_workflow_clean.yml")


def test_clean_workflow_has_no_findings():
    findings = scan_file(FIXTURE)
    assert findings == [], f"Rules fired on a clean workflow: {[f.rule_id for f in findings]}"
