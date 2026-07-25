from typing import Any

from .base import BaseRule, Finding, Severity


class PersistCredentialsRule(BaseRule):
    rule_id = "FS015"
    title = "Persist Credentials — GitHub Token Remains in Git Config After Checkout"
    severity = Severity.MEDIUM

    def check(self, config: dict[Any, Any], file_path: str, platform: str = "github") -> list[Finding]:
        if platform != "github":
            return []
        findings: list[Finding] = []
        jobs = config.get("jobs", {})
        if not isinstance(jobs, dict):
            return findings
        for job in jobs.values():
            if not isinstance(job, dict):
                continue
            for step in job.get("steps", []):
                if not isinstance(step, dict):
                    continue
                if not step.get("uses", "").startswith("actions/checkout"):
                    continue
                with_params = step.get("with", {}) or {}
                # Default for persist-credentials is True — only safe when explicitly False
                persist = with_params.get("persist-credentials", True)
                if persist is False or str(persist).lower() == "false":
                    continue
                findings.append(Finding(
                    rule_id=self.rule_id,
                    title=self.title,
                    severity=self.severity,
                    description="actions/checkout is used without 'persist-credentials: false'. By default the GITHUB_TOKEN is written to .git/config and remains accessible to every subsequent step in the job, including any action or script that runs after checkout. A compromised dependency or injected step can read the token and use it to push code or access other APIs.",
                    remediation="Add 'persist-credentials: false' to the actions/checkout 'with:' block. If downstream steps need git authentication, use a separate scoped token passed explicitly rather than relying on the persisted credential.",
                    mitre_technique="T1552.001",
                    owasp_category="CICD-SEC-6",
                    file_path=file_path,
                ))
        return findings
