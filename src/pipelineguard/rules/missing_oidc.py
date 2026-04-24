from typing import Any
from .base import BaseRule, Finding, Severity


class MissingOIDCRule(BaseRule):
    rule_id = "FS004"
    title = "Missing OIDC — Long-Lived Cloud Credential in Use"
    severity = Severity.HIGH #
    
    SAFE_PATTERNS = [
    "aws-actions/", "azure/login", "google-github-actions/"
    ]

    def _extract_uses(self, config: dict[str, Any], ) -> list[str]:
        uses = []
        jobs = config.get("jobs", {})
        for job in jobs.values():
            for step in job.get("steps", []):
                if "uses" in step:
                    uses.append(step["uses"])
        return uses

    def _extract_permissions(self, config: dict[str, Any]) -> Any:
        return config.get("permissions", None)

    def check(self, config: dict[str, Any], file_path: str, platform: str = "github") -> list[Finding]:
        if platform != "github":
            return []        
        findings = []
        uses = self._extract_uses(config)
        permissions = self._extract_permissions(config)

        uses_cloud_provider = any(
            any(pattern in step for pattern in self.SAFE_PATTERNS)
            for step in uses
        )

        has_oidc = (
            isinstance(permissions, dict) and
            permissions.get("id-token") == "write"
        )

        if uses_cloud_provider and not has_oidc:
            findings.append(Finding(
                rule_id=self.rule_id,
                title=self.title,
                severity=self.severity,
                description=f"This pipeline connects to a cloud provider but does not use OIDC for authentication. Long-lived credentials stored as secrets can be stolen through a compromised action or leaked pipeline log and will remain valid until manually rotated.",
                remediation="Add 'id-token: write' to the workflow permissions block and replace long-lived credential secrets with a role-to-assume (AWS) or client-id/tenant-id (Azure). This ensures credentials expire automatically after each run.",
                mitre_technique="T1552.004",
                file_path=file_path,
                owasp_category="CICD-SEC-6",

            ))

        return findings