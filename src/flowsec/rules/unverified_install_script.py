import re
from typing import Any
from .base import BaseRule, Finding, Severity


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
        findings = []
        commands = self._get_commands(config, platform)

        for command in commands:
            for line in command.split("\n"):
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
                        ))
                        break  # one finding per line
        return findings
