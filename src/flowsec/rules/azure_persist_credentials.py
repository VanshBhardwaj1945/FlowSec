from typing import Any

from .base import BaseRule, Finding, Severity


class AzurePersistCredentialsRule(BaseRule):
    rule_id = "FS036"
    title = "Persist Credentials — Azure Checkout Leaves Token in Git Config"
    severity = Severity.MEDIUM

    def _iter_steps(self, config: dict[Any, Any]) -> list[dict[Any, Any]]:
        steps: list[dict[Any, Any]] = []
        top_steps = config.get("steps")
        if isinstance(top_steps, list):
            steps.extend(s for s in top_steps if isinstance(s, dict))
        jobs = config.get("jobs")
        if isinstance(jobs, list):
            for job in jobs:
                if isinstance(job, dict) and isinstance(job.get("steps"), list):
                    steps.extend(s for s in job["steps"] if isinstance(s, dict))
        return steps

    def check(self, config: dict[Any, Any], file_path: str, platform: str = "azure") -> list[Finding]:
        if platform != "azure":
            return []
        findings: list[Finding] = []
        for step in self._iter_steps(config):
            # Azure checkout steps look like: - checkout: self / persistCredentials: true
            if "checkout" not in step:
                continue
            persist = step.get("persistCredentials")
            if persist is not None and str(persist).lower() == "true":
                findings.append(Finding(
                    rule_id=self.rule_id,
                    title=self.title,
                    severity=self.severity,
                    description="An Azure DevOps checkout step sets 'persistCredentials: true'. The System.AccessToken is written to the local git config and stays readable by every later step in the job, including any script or task that runs after checkout.",
                    remediation="Remove 'persistCredentials: true' (the default is false). If a later step needs git authentication, provide a narrowly scoped token explicitly instead of persisting the pipeline token.",
                    mitre_technique="T1552.001",
                    owasp_category="CICD-SEC-6",
                    file_path=file_path,
                ))
        return findings
