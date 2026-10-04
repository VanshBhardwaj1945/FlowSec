from typing import Any

from .base import BaseRule, Finding, Severity, numbered_lines, pipeline_commands


class EnvVarsInLogsRule(BaseRule):
    rule_id = "FS025"
    title = "Environment Variables Printed to Logs — Secrets Exposed in Pipeline Output"
    severity = Severity.MEDIUM

    DANGEROUS_COMMANDS = ["printenv", "env ", "env\n", "env|", "env |"]

    def _get_commands(self, config: dict[Any, Any], platform: str) -> list[str]:
        return pipeline_commands(config, platform)

    def check(self, config: dict[Any, Any], file_path: str, platform: str = "github") -> list[Finding]:
        findings: list[Finding] = []
        commands = self._get_commands(config, platform)

        for command in commands:
            for line_no, line in numbered_lines(command):
                line_stripped = line.strip()
                line_lower = line_stripped.lower()

                is_dangerous = (
                    any(cmd in line_lower for cmd in self.DANGEROUS_COMMANDS) or
                    line_lower.startswith("echo $") or
                    line_lower.startswith("echo ${")
                )

                if is_dangerous:
                    findings.append(Finding(
                        rule_id=self.rule_id,
                        title=self.title,
                        severity=self.severity,
                        description=f"Pipeline step prints environment variables to logs: '{line_stripped}'. Pipeline logs are visible to all repo contributors and sometimes publicly accessible, exposing any secrets stored as environment variables.",
                        remediation="Remove commands that print environment variables to logs. If you need to debug, use GitHub's built-in secret masking by referencing secrets through the secrets context instead of environment variables.",
                        mitre_technique="T1552.001",
                        owasp_category="CICD-SEC-6",
                        file_path=file_path,
                        line_number=line_no,
                    ))
        return findings