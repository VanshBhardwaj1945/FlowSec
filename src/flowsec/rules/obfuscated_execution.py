from typing import Any

from .base import BaseRule, Finding, Severity, numbered_lines, pipeline_commands


class ObfuscatedExecutionRule(BaseRule):
    rule_id = "FS037"
    title = "Obfuscated Execution — Encoded Payload Piped to a Shell"
    severity = Severity.MEDIUM

    SHELLS = ("bash", "sh", "zsh", "python", "python3", "node")

    def _get_commands(self, config: dict[Any, Any], platform: str) -> list[str]:
        return pipeline_commands(config, platform)

    def _is_obfuscated(self, line: str) -> bool:
        lowered = line.lower()
        decodes = "base64 -d" in lowered or "base64 --decode" in lowered or "base64 -di" in lowered
        pipes_to_shell = "|" in line and any(f"| {sh}" in lowered or f"|{sh}" in lowered for sh in self.SHELLS)
        return decodes and pipes_to_shell

    def check(self, config: dict[Any, Any], file_path: str, platform: str = "github") -> list[Finding]:
        findings: list[Finding] = []
        for command in self._get_commands(config, platform):
            for line_no, line in numbered_lines(command):
                if self._is_obfuscated(line):
                    findings.append(Finding(
                        rule_id=self.rule_id,
                        title=self.title,
                        severity=self.severity,
                        description=f"An encoded payload is decoded and piped straight into a shell: '{line.strip()}'. Base64-decoding into an interpreter hides what actually runs from code review and from scanners, and is a common way to smuggle malicious commands past a pipeline audit.",
                        remediation="Do not decode-and-execute in pipelines. Commit the script in plain text so it can be reviewed, and run it directly.",
                        mitre_technique="T1027",
                        owasp_category="CICD-SEC-3",
                        file_path=file_path,
                        line_number=line_no,
                    ))
        return findings
