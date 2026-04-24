from typing import Any
from .base import BaseRule, Finding, Severity


class MissingTimeoutRule(BaseRule):
    rule_id = "FS006"
    title = "Missing Timeout — Job Runs Up to 6 Hours Unchecked"
    severity = Severity.LOW

    def check(self, config: dict[str, Any], file_path: str, platform: str = "github") -> list[Finding]:
        findings = []

        if platform == "github":
            jobs = config.get("jobs", {})
            for job_name, job in jobs.items():
                if not isinstance(job, dict):
                    continue
                if "timeout-minutes" not in job:
                    findings.append(Finding(
                        rule_id=self.rule_id,
                        title=self.title,
                        severity=self.severity,
                        description=f"Job '{job_name}' has no timeout defined. GitHub's default timeout is 6 hours.",
                        remediation=f"Add 'timeout-minutes: 15' to job '{job_name}'.",
                        mitre_technique="T1499",
                        owasp_category="CICD-SEC-10",
                        file_path=file_path,
                    ))

        elif platform == "gitlab":
            for key, value in config.items():
                if not isinstance(value, dict):
                    continue
                if "script" in value and "timeout" not in value:
                    findings.append(Finding(
                        rule_id=self.rule_id,
                        title=self.title,
                        severity=self.severity,
                        description=f"GitLab job '{key}' has no timeout defined. GitLab's default timeout is 1 hour.",
                        remediation=f"Add 'timeout: 15 minutes' to job '{key}'.",
                        mitre_technique="T1499",
                        owasp_category="CICD-SEC-10",
                        file_path=file_path,
                    ))

        elif platform == "azure":
            jobs = config.get("jobs", [])
            if isinstance(jobs, list):
                for job in jobs:
                    if not isinstance(job, dict):
                        continue
                    job_name = job.get("job", "unknown")
                    if "timeoutInMinutes" not in job:
                        findings.append(Finding(
                            rule_id=self.rule_id,
                            title=self.title,
                            severity=self.severity,
                            description=f"Azure DevOps job '{job_name}' has no timeout defined.",
                            remediation=f"Add 'timeoutInMinutes: 15' to job '{job_name}'.",
                            mitre_technique="T1499",
                            owasp_category="CICD-SEC-10",
                            file_path=file_path,
                        ))

        return findings