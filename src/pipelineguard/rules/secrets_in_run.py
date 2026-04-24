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

    def _check_commands(self, commands: list[str], file_path: str) -> list[Finding]:
        findings = []
        for command in commands:
            for line in command.split("\n"):
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
                            ))
                            break
        return findings

    def check(self, config: dict[str, Any], file_path: str, platform: str = "github") -> list[Finding]:
        findings = []

        if platform == "github":
            jobs = config.get("jobs", {})
            for job in jobs.values():
                if not isinstance(job, dict):
                    continue
                for step in job.get("steps", []):
                    if not isinstance(step, dict):
                        continue
                    run = step.get("run", "")
                    if run:
                        findings.extend(self._check_commands([run], file_path))

        elif platform in ("gitlab", "azure"):
            for key, value in config.items():
                if not isinstance(value, dict):
                    continue
                scripts = value.get("script", [])
                if isinstance(scripts, str):
                    scripts = [scripts]
                if isinstance(scripts, list):
                    string_scripts = [s for s in scripts if isinstance(s, str)]
                    findings.extend(self._check_commands(string_scripts, file_path))

        return findings