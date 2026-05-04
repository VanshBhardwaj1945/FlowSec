from typing import Any
from .base import BaseRule, Finding, Severity


class EnvVarsInLogsRule(BaseRule):
    rule_id = "FS025"
    title = "Environment Variables Printed to Logs — Secrets Exposed in Pipeline Output"
    severity = Severity.MEDIUM

    DANGEROUS_COMMANDS = ["printenv", "env ", "env\n", "env|", "env |"]

    def _get_commands(self, config: dict[str, Any], platform: str) -> list[str]:
        commands = []
        if platform == "github":
            for job in config.get("jobs", {}).values():
                if not isinstance(job, dict):
                    continue
                for step in job.get("steps", []):
                    if isinstance(step, dict) and step.get("run"):
                        commands.append(step["run"])
        elif platform in ("gitlab", "azure"):
            for value in config.values():
                if not isinstance(value, dict):
                    continue
                scripts = value.get("script", [])
                if isinstance(scripts, str):
                    scripts = [scripts]
                if isinstance(scripts, list):
                    commands.extend([s for s in scripts if isinstance(s, str)])
        return commands

    def check(self, config: dict[str, Any], file_path: str, platform: str = "github") -> list[Finding]:
        findings = []
        commands = self._get_commands(config, platform)

        for command in commands:
            for line in command.split("\n"):
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
                    ))
        return findings