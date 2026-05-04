from typing import Any
from .base import BaseRule, Finding, Severity


class InsecureCurlRule(BaseRule):
    rule_id = "FS023"
    title = "Insecure curl — SSL Verification Disabled in Pipeline"
    severity = Severity.HIGH

    INSECURE_FLAGS = ["curl -k ", "curl -k\n", "curl --insecure", "curl -k\"", "curl -k'"]

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
                if any(flag in line_stripped for flag in self.INSECURE_FLAGS):
                    findings.append(Finding(
                        rule_id=self.rule_id,
                        title=self.title,
                        severity=self.severity,
                        description=f"curl is used with SSL verification disabled: '{line_stripped}'. This allows an attacker to perform a man-in-the-middle attack and serve malicious content to your pipeline.",
                        remediation="Remove the -k or --insecure flag from curl commands. If you're hitting a self-signed certificate, add it to your trusted certificates instead of disabling verification entirely.",
                        mitre_technique="T1071",
                        owasp_category="CICD-SEC-3",
                        file_path=file_path,
                    ))
        return findings