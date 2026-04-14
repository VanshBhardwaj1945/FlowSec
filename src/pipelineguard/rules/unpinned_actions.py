from typing import Any
from .base import BaseRule, Finding, Severity


class UnpinnedActionsRule(BaseRule):
    rule_id = "FS002"
    title = "Unipinned Actions"
    severity = Severity.CRITICAL   # Supply chain attacks are in OWASP top 10 right now (04/14/2026)
    

    def _extract_uses(self, config: dict[str, Any]) -> dict[str, str]:
        uses = []                                   # Creating list of ENV Variable
        jobs = config.get("jobs", {})                   # jobs is set too whats inside {} for jobs
        for job in jobs.values():
            for step in job.get("steps",[]):
                if "uses" in step:
                    uses.append(step["uses"])
        return uses

            

    def check(self, config: dict[str, Any], file_path: str) -> list[Finding]:
        findings = []
        uses = self._extract_uses(config)

        for use in uses:
            before, separator, after = use.partition("@") 
            is_pinned = len(after) == 40 and all(c in "0123456789abcdef" for c in after)

            if not is_pinned:
                findings.append(Finding( 
                    rule_id=self.rule_id,
                    title=self.title,
                    severity=self.severity,
                    description=f"Action '{use}' is not pinned to a commit hash",
                    remediation=f"Pin '{use}' to a full commit SHA instead of a branch or tag. Example: actions/checkout@b4ffde65f46336ab88eb53be808477a3936bae1",
                    mitre_technique="T1195.001",
                    file_path=file_path,
                ))

        return findings
