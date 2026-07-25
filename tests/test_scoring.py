from flowsec.rules.base import Finding, Severity
from flowsec.scoring import compute_risk_score


def make_finding(severity: Severity) -> Finding:
    return Finding(
        rule_id="FS000",
        title="Test finding",
        severity=severity,
        description="test",
        remediation="test",
        mitre_technique="T0000",
        file_path="test.yml",
    )


def test_no_findings_scores_zero():
    assert compute_risk_score([]) == 0


def test_score_stays_within_bounds():
    findings = [make_finding(Severity.CRITICAL) for _ in range(50)]
    assert 0 <= compute_risk_score(findings) <= 100


def test_critical_scores_higher_than_low():
    critical_score = compute_risk_score([make_finding(Severity.CRITICAL)])
    low_score = compute_risk_score([make_finding(Severity.LOW)])
    assert critical_score > low_score


def test_more_findings_score_higher():
    one = compute_risk_score([make_finding(Severity.HIGH)])
    three = compute_risk_score([make_finding(Severity.HIGH) for _ in range(3)])
    assert three > one


def test_many_criticals_approach_max():
    findings = [make_finding(Severity.CRITICAL) for _ in range(20)]
    assert compute_risk_score(findings) >= 90
