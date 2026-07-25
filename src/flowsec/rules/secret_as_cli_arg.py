import re
from typing import Any
from .base import BaseRule, Finding, Severity


class SecretAsCLIArgRule(BaseRule):
    rule_id = "FS018"
    title = "Secret as CLI Argument — Credential Exposed in Process List"
    severity = Severity.HIGH

    SECRET_FLAGS = [
        "--token", "--password", "--passwd", "--secret",
        "--api-key", "--apikey", "--api_key", "--auth-token",
        "--access-token", "--private-key", "--client-secret",
        "--credentials", "--authorization",
    ]

    def _check_lines(self, commands: list[str], file_path: str, platform: str) -> list[Finding]:
        findings = []
        seen: set[str] = set()
        for command in commands:
            for line in command.split("\n"):
                line_stripped = line.strip()
                for flag in self.SECRET_FLAGS:
                    if flag not in line_stripped:
                        continue
                    if platform == "github":
                        match = re.search(re.escape(flag) + r"\s+\$\{\{", line_stripped)
                    else:
                        match = re.search(re.escape(flag) + r"\s+\$\w+", line_stripped)
                    if match and line_stripped not in seen:
                        seen.add(line_stripped)
                        findings.append(Finding(
                            rule_id=self.rule_id,
                            title=self.title,
                            severity=self.severity,
                            description=f"Secret passed directly as CLI argument '{flag}': '{line_stripped}'. Command-line arguments are visible to all processes running as the same user via /proc and may be captured in runner audit logs or third-party observability tools.",
                            remediation="Pass the secret via an environment variable and use the tool's environment variable equivalent. Most CLIs support e.g. TOKEN env var instead of --token flag. Set it in the step's 'env:' block and remove the flag from the command.",
                            mitre_technique="T1552",
                            owasp_category="CICD-SEC-6",
                            file_path=file_path,
                        ))
                        break
        return findings

    def _get_commands(self, config: dict[str, Any], platform: str) -> list[str]:
        commands: list[str] = []
        if platform == "github":
            jobs = config.get("jobs", {})
            if not isinstance(jobs, dict):
                return commands
            for job in jobs.values():
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
                    commands.extend(s for s in scripts if isinstance(s, str))
        return commands

    def check(self, config: dict[str, Any], file_path: str, platform: str = "github") -> list[Finding]:
        return self._check_lines(self._get_commands(config, platform), file_path, platform)
