from typing import Any

from .base import BaseRule, Finding, Severity, numbered_lines, pipeline_commands


class InsecureCurlRule(BaseRule):
    rule_id = "FS023"
    title = "Insecure curl — SSL Verification Disabled in Pipeline"
    severity = Severity.HIGH

    INSECURE_FLAGS = ["curl -k ", "curl -k\n", "curl --insecure", "curl -k\"", "curl -k'"]

    def _get_commands(self, config: dict[Any, Any], platform: str) -> list[str]:
        return pipeline_commands(config, platform)

    def check(self, config: dict[Any, Any], file_path: str, platform: str = "github") -> list[Finding]:
        findings: list[Finding] = []
        commands = self._get_commands(config, platform)

        for command in commands:
            for line_no, line in numbered_lines(command):
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
                        line_number=line_no,
                    ))
        return findings