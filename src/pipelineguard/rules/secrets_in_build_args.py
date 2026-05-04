from typing import Any
from .base import BaseRule, Finding, Severity

SUSPICIOUS_PATTERNS = [
    "api_key", "apikey", "token", "secret", "password",
    "passwd", "private_key", "client_secret", "auth",
]


class SecretsInBuildArgsRule(BaseRule):
    rule_id = "FS021"
    title = "Secret in Docker Build Argument — Credential Stored in Image History"
    severity = Severity.HIGH

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
                line_lower = line.lower().strip()
                if "docker build" in line_lower and "--build-arg" in line_lower:
                    if any(pattern in line_lower for pattern in SUSPICIOUS_PATTERNS):
                        findings.append(Finding(
                            rule_id=self.rule_id,
                            title=self.title,
                            severity=self.severity,
                            description=f"Docker build argument appears to contain a secret: '{line.strip()}'. Build arguments are stored in image layer history and can be read by anyone with access to the image using 'docker history'.",
                            remediation="Never pass secrets as Docker build arguments. Use Docker secrets, BuildKit secret mounts, or pass secrets at runtime via environment variables instead.",
                            mitre_technique="T1552.001",
                            owasp_category="CICD-SEC-6",
                            file_path=file_path,
                        ))
                        break
        return findings