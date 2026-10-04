from typing import Any

from .base import BaseRule, Finding, Severity, numbered_lines, pipeline_commands

SUSPICIOUS_PATTERNS = [
    "password=", "passwd=", "token=", "api_key=", "apikey=",
    "secret=", "Authorization: Bearer", "Authorization: Token",
    "access_key=", "private_key=", "client_secret=",
]


class SecretsInRunRule(BaseRule):
    rule_id = "FS010"
    title = "Secret in Run Command — Plaintext Credential in Shell Step"
    severity = Severity.CRITICAL

    def _check_commands(self, commands: list[str], file_path: str) -> list[Finding]:
        findings: list[Finding] = []
        for command in commands:
            for line_no, line in numbered_lines(command):
                line_lower = line.lower()
                for pattern in SUSPICIOUS_PATTERNS:
                    if pattern.lower() in line_lower:
                        after = line_lower.split(pattern.lower(), 1)[1].strip()
                        if after and not after.startswith("${{") and not after.startswith("${"):
                            findings.append(Finding(
                                rule_id=self.rule_id,
                                title=self.title,
                                severity=self.severity,
                                description=f"Run command contains what appears to be a hardcoded credential matching pattern '{pattern}'.",
                                remediation="Move the credential to your platform's secret manager and reference it as an environment variable.",
                                mitre_technique="T1552.001",
                                owasp_category="CICD-SEC-6",
                                file_path=file_path,
                                line_number=line_no,
                            ))
                            break
        return findings

    def check(self, config: dict[Any, Any], file_path: str, platform: str = "github") -> list[Finding]:
        return self._check_commands(pipeline_commands(config, platform), file_path)
