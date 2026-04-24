from typing import Any
from .base import BaseRule, Finding, Severity

DEPLOY_KEYWORDS = ["deploy", "release", "publish", "prod", "production", "ship"]

class MissingEnvProtectionRule(BaseRule):
    rule_id = "FS012"
    title = "Missing Environment Protection — Deploy Job Has No Approval Gate"
    severity = Severity.HIGH

    def check(self, config: dict[str, Any], file_path: str, platform: str = "github") -> list[Finding]:
        if platform != "github":
            return []
        findings = []
        jobs = config.get("jobs", {})

        for job_name, job in jobs.items():
            job_name_lower = job_name.lower()
            is_deploy = any(keyword in job_name_lower for keyword in DEPLOY_KEYWORDS)

            if is_deploy and not job.get("environment"):
                findings.append(Finding(
                    rule_id=self.rule_id,
                    title=self.title,
                    severity=self.severity,
                    description=f"Job '{job_name}' appears to be a deployment job but has no GitHub Environment configured. Without environment protection rules, deployments to production can happen automatically with no human approval required.",
                    remediation="Add an 'environment: production' key to this job and configure required reviewers in your GitHub repository's Environment settings. This adds a manual approval gate before any production deployment.",
                    mitre_technique="T1078",
                    owasp_category="CICD-SEC-5",
                    file_path=file_path,
                ))

        return findings