import math

from .rules.base import Finding

SEVERITY_WEIGHTS = {"critical": 10, "high": 5, "medium": 3, "low": 1}


def compute_risk_score(findings: list[Finding]) -> int:
    if not findings:
        return 0

    counts: dict[str, int] = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for f in findings:
        counts[f.severity.value] += 1

    raw = 0.0
    for sev, weight in SEVERITY_WEIGHTS.items():
        count = counts[sev]
        if count == 0:
            continue
        raw += weight
        for n in range(2, count + 1):
            raw += weight / math.sqrt(n)

    score = round(100 * (1 - math.exp(-raw / 30)))
    return min(100, max(0, score))
