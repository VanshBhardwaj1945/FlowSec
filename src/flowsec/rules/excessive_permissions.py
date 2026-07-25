from typing import Any
from .base import BaseRule, Finding, Severity


class ExcessivePermissions(BaseRule):
    rule_id = "FS003"
    title = "Excessive Permissions — Overprivileged Workflow Token"
    severity = Severity.HIGH #
    
    SUSPICIOUS_PATTERNS = [
        "write-all", "read-all"
    ]

    def _extract_permissions_(self, config: dict[str, Any]) -> Any:
        return config.get("permissions", None)

        
            

    def check(self, config: dict[str, Any], file_path: str, platform: str = "github") -> list[Finding]:
        if platform != "github":
            return []        
        findings = []
        permission = self._extract_permissions_(config)

        if (permission in self.SUSPICIOUS_PATTERNS) or (permission is None) :
            findings.append(Finding( 
                rule_id = self.rule_id,
                title = self.title,
                severity = self.severity,
                description = f"Pipeline permissions are set to '{permission}' giving the workflow token broad access across the repository. An attacker who compromises this pipeline can read code, write to branches, modify releases, and exfiltrate secrets.",
                remediation = f"Define permissions explicitly at the workflow level using least privilege. Only grant the specific scopes the job needs. Example: 'permissions: contents: read'. Never use write-all or read-all.",
                mitre_technique="T1078",
                file_path=file_path,
                owasp_category="CICD-SEC-5",

            ))
            

        return findings
