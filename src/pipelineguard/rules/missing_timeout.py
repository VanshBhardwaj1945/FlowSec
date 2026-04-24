from typing import Any
from .base import BaseRule, Finding, Severity


class MissingTimeoutRule(BaseRule):
    rule_id = "FS006"
    title = "Missing Timeout — Job Runs Up to 6 Hours Unchecked"
    severity = Severity.LOW

    def check(self, config: dict[str, Any], file_path: str) -> list[Finding]:
        findings = []
        jobs = config.get("jobs", {})

        for job_name, job in jobs.items():
            if "timeout-minutes" not in job:
                findings.append(Finding(
                    rule_id=self.rule_id,
                    title=self.title,
                    severity=self.severity,
                    description=f"Job '{job_name}' has no timeout defined. GitHub's default timeout is 6 hours. A hanging job — caused by an infinite loop, a stuck test, or a deliberate denial of service attack — will consume runner minutes for the full 6 hours, running up costs and blocking other workflows.",
                    remediation=f"Add 'timeout-minutes' to job '{job_name}'. A reasonable default for most jobs is 15-30 minutes. Example: timeout-minutes: 15",
                    mitre_technique="T1499",
                    file_path=file_path,
                    owasp_category="CICD-SEC-10",

                ))

        return findings