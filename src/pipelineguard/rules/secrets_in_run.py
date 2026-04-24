from typing import Any
from .base import BaseRule, Finding, Severity

SUSPICIOUS_PATTERNS = [
    "password=", "passwd=", "token=", "api_key=", "apikey=",
    "secret=", "Authorization: Bearer", "Authorization: Token",
    "access_key=", "private_key=", "client_secret=",
]

class SecretsInRunRule(BaseRule):
    rule_id = "FS010"
    title = "Secret in Run Command — Plaintext Credential in Shell Step"
    severity = Severity.CRITICAL

    def check(self, config: dict[str, Any], file_path: str) -> list[Finding]:
        findings = []
        jobs = config.get("jobs", {})

        for job in jobs.values():
            for step in job.get("steps", []):
                run = step.get("run", "")
                if not run:
                    continue
                for line in run.split("\n"):
                    line_lower = line.lower()
                    for pattern in SUSPICIOUS_PATTERNS:
                        if pattern.lower() in line_lower:
                            after = line_lower.split(pattern.lower(), 1)[1].strip()
                            if after and not after.startswith("${{"):
                                findings.append(Finding(
                                    rule_id=self.rule_id,
                                    title=self.title,
                                    severity=self.severity,
                                    description=f"Run command contains what appears to be a hardcoded credential matching pattern '{pattern}'. Credentials in shell commands are visible in pipeline logs and committed to git history.",
                                    remediation="Move the credential to GitHub Secrets and reference it as an environment variable. Never pass secrets as command line arguments.",
                                    mitre_technique="T1552.001",
                                    owasp_category="CICD-SEC-6",
                                    file_path=file_path,
                                ))
                                break

        return findings