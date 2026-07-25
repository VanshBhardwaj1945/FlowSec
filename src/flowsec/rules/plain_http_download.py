from typing import Any

from .base import BaseRule, Finding, Severity


class PlainHTTPDownloadRule(BaseRule):
    rule_id = "FS034"
    title = "Plain-HTTP Download — Unencrypted Fetch in Pipeline"
    severity = Severity.MEDIUM

    DOWNLOAD_PREFIXES = ("curl", "wget")

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
                stripped = line.strip()
                uses_downloader = any(stripped.startswith(p) or f" {p} " in stripped for p in self.DOWNLOAD_PREFIXES)
                if uses_downloader and "http://" in stripped:
                    findings.append(Finding(
                        rule_id=self.rule_id,
                        title=self.title,
                        severity=self.severity,
                        description=f"A file is downloaded over plain HTTP: '{stripped}'. An on-path attacker can replace the response with malicious content, and there is no transport encryption or server authentication at all.",
                        remediation="Use https:// for all downloads. If the resource is executed or installed, also verify a published SHA-256 checksum after downloading.",
                        mitre_technique="T1071",
                        owasp_category="CICD-SEC-3",
                        file_path=file_path,
                    ))
        return findings
