from typing import Any
from .base import BaseRule, Finding, Severity

PACKAGE_MANAGERS = ["pip install", "pip3 install", "npm install", "yarn add", "npm i"]


class DependencyPinningRule(BaseRule):
    rule_id = "FS009"
    title = "Unpinned Dependency — Package Installed Without Version Lock"
    severity = Severity.HIGH

    def _is_pinned(self, command: str) -> bool:
        for manager in PACKAGE_MANAGERS:
            if manager in command:
                parts = command.split(manager, 1)
                if len(parts) < 2:
                    return False
                packages = parts[1].strip().split()
                for pkg in packages:
                    if pkg.startswith("-"):
                        continue
                    if "==" not in pkg and "@" not in pkg:
                        return False
        return True

    def _check_commands(self, commands: list[str], file_path: str) -> list[Finding]:
        findings = []
        for command in commands:
            for line in command.split("\n"):
                line = line.strip()
                for manager in PACKAGE_MANAGERS:
                    if manager in line and not self._is_pinned(line):
                        findings.append(Finding(
                            rule_id=self.rule_id,
                            title=self.title,
                            severity=self.severity,
                            description=f"Command '{line.strip()}' installs dependencies without version pins.",
                            remediation="Pin all dependencies to exact versions. Use 'pip install requests==2.31.0' instead of 'pip install requests'.",
                            mitre_technique="T1195.002",
                            owasp_category="CICD-SEC-3",
                            file_path=file_path,
                        ))
                        break
        return findings

    def check(self, config: dict[str, Any], file_path: str, platform: str = "github") -> list[Finding]:
        findings = []

        if platform == "github":
            jobs = config.get("jobs", {})
            for job in jobs.values():
                if not isinstance(job, dict):
                    continue
                for step in job.get("steps", []):
                    if not isinstance(step, dict):
                        continue
                    run = step.get("run", "")
                    if run:
                        findings.extend(self._check_commands([run], file_path))

        elif platform in ("gitlab", "azure"):
            for key, value in config.items():
                if not isinstance(value, dict):
                    continue
                scripts = value.get("script", [])
                if isinstance(scripts, str):
                    scripts = [scripts]
                if isinstance(scripts, list):
                    string_scripts = [s for s in scripts if isinstance(s, str)]
                    findings.extend(self._check_commands(string_scripts, file_path))

        return findings