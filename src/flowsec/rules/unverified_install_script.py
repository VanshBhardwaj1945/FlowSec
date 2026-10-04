import re
from typing import Any

from .base import BaseRule, Finding, Severity, numbered_lines, pipeline_commands


class UnverifiedInstallScriptRule(BaseRule):
    rule_id = "FS019"
    title = "Unverified Install Script — Remote Code Fetched and Executed Directly"
    severity = Severity.HIGH

    PIPE_PATTERNS = [
        re.compile(r"curl\s+\S.*\|\s*(ba)?sh", re.IGNORECASE),
        re.compile(r"wget\s+\S.*\|\s*(ba)?sh", re.IGNORECASE),
        re.compile(r"(ba)?sh\s+<\s*\(\s*curl", re.IGNORECASE),
        re.compile(r"(ba)?sh\s+<\s*\(\s*wget", re.IGNORECASE),
        re.compile(r"curl\s+\S[^&\n]*&&\s*(ba)?sh\s+\S+\.sh", re.IGNORECASE),
        re.compile(r"wget\s+\S[^&\n]*&&\s*(ba)?sh\s+\S+\.sh", re.IGNORECASE),
    ]

    def _get_commands(self, config: dict[Any, Any], platform: str) -> list[str]:
        return pipeline_commands(config, platform)

    def check(self, config: dict[Any, Any], file_path: str, platform: str = "github") -> list[Finding]:
        findings: list[Finding] = []
        commands = self._get_commands(config, platform)

        for command in commands:
            for line_no, line in numbered_lines(command):
                line_stripped = line.strip()
                for pattern in self.PIPE_PATTERNS:
                    if pattern.search(line_stripped):
                        findings.append(Finding(
                            rule_id=self.rule_id,
                            title=self.title,
                            severity=self.severity,
                            description=f"Remote script fetched and executed without integrity verification: '{line_stripped}'. If the remote server, CDN, or DNS is compromised, an attacker can serve a malicious payload that executes with full pipeline privileges. This is a common supply chain attack vector.",
                            remediation="Download the script first, verify its SHA-256 checksum, then execute: 'curl -fsSL -o install.sh <url> && echo \"<expected_sha256>  install.sh\" | sha256sum -c && bash install.sh'. For maximum safety, vendor the script in your repository and reference the local copy.",
                            mitre_technique="T1195.002",
                            owasp_category="CICD-SEC-3",
                            file_path=file_path,
                            line_number=line_no,
                        ))
                        break  # one finding per line
        return findings
