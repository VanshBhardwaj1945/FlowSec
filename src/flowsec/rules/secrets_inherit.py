from typing import Any

from .base import BaseRule, Finding, Severity


class SecretsInheritRule(BaseRule):
    rule_id = "FS030"
    title = "secrets: inherit — All Secrets Passed to Called Workflow"
    severity = Severity.MEDIUM

    def check(self, config: dict[Any, Any], file_path: str, platform: str = "github") -> list[Finding]:
        if platform != "github":
            return []
        findings: list[Finding] = []
        jobs = config.get("jobs", {})
        if not isinstance(jobs, dict):
            return findings
        for job_name, job in jobs.items():
            if isinstance(job_name, str) and job_name.startswith("__line_"):
                continue
            if not isinstance(job, dict):
                continue
            secrets = job.get("secrets")
            if isinstance(secrets, str) and secrets.strip() == "inherit":
                findings.append(Finding(
                    rule_id=self.rule_id,
                    title=self.title,
                    severity=self.severity,
                    description=f"Job '{job_name}' calls a reusable workflow with 'secrets: inherit', which passes every secret in this repository to the called workflow. If the called workflow is compromised or only needs one or two secrets, this hands it far more access than required.",
                    remediation="Pass only the secrets the called workflow needs, explicitly: 'secrets: { MY_TOKEN: ${{ secrets.MY_TOKEN }} }'. Reserve 'inherit' for workflows you fully control and that genuinely need broad access.",
                    mitre_technique="T1078",
                    owasp_category="CICD-SEC-5",
                    file_path=file_path,
                ))
        return findings
