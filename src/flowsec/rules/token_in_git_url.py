import re
from typing import Any

from .base import BaseRule, Finding, Severity


class TokenInGitURLRule(BaseRule):
    rule_id = "FS028"
    title = "Credential in Git URL — Token Leaked to Logs and History"
    severity = Severity.HIGH

    # https://user:password@host  or  https://token@host
    CREDENTIAL_URL = re.compile(r"https?://[^/\s:@]+:[^/\s@]+@")

    def _get_commands(self, config: dict[Any, Any], platform: str) -> list[str]:
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
                    commands.extend([s for s in scripts if isinstance(s, str)])
        return commands

    def check(self, config: dict[Any, Any], file_path: str, platform: str = "github") -> list[Finding]:
        findings: list[Finding] = []
        for command in self._get_commands(config, platform):
            for line in command.split("\n"):
                if self.CREDENTIAL_URL.search(line):
                    findings.append(Finding(
                        rule_id=self.rule_id,
                        title=self.title,
                        severity=self.severity,
                        description=f"A credential is embedded directly in a URL: '{line.strip()}'. Credentials in URLs are written to shell history, the process list, git remote config, and any command echo in the pipeline log — all of which are readable long after the run.",
                        remediation="Never put a token or password in a URL. Use a git credential helper, an Authorization header from an environment variable, or the platform's built-in checkout with a scoped token.",
                        mitre_technique="T1552.001",
                        owasp_category="CICD-SEC-6",
                        file_path=file_path,
                    ))
        return findings
