import re
from typing import Any

from .base import BaseRule, Finding, Severity, numbered_lines, pipeline_commands


class TokenInGitURLRule(BaseRule):
    rule_id = "FS028"
    title = "Credential in Git URL — Token Leaked to Logs and History"
    severity = Severity.HIGH

    # https://user:password@host  or  https://token@host
    CREDENTIAL_URL = re.compile(r"https?://[^/\s:@]+:[^/\s@]+@")

    def _get_commands(self, config: dict[Any, Any], platform: str) -> list[str]:
        return pipeline_commands(config, platform)

    def check(self, config: dict[Any, Any], file_path: str, platform: str = "github") -> list[Finding]:
        findings: list[Finding] = []
        for command in self._get_commands(config, platform):
            for line_no, line in numbered_lines(command):
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
                        line_number=line_no,
                    ))
        return findings
