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

    def check(self, config: dict[str, Any], file_path: str) -> list[Finding]:
        findings = []
        jobs = config.get("jobs", {})

        for job in jobs.values():
            for step in job.get("steps", []):
                run = step.get("run", "")
                if not run:
                    continue
                for line in run.split("\n"):
                    line = line.strip()
                    for manager in PACKAGE_MANAGERS:
                        if manager in line and not self._is_pinned(line):
                            findings.append(Finding(
                                rule_id=self.rule_id,
                                title=self.title,
                                severity=self.severity,
                                description=f"Package manager command '{line.strip()}' installs dependencies without version pins. An attacker who publishes a malicious version of a dependency could have it automatically installed in your pipeline.",
                                remediation="Pin all dependencies to exact versions. Use 'pip install requests==2.31.0' instead of 'pip install requests'. Better yet use a requirements.txt or package-lock.json with pinned versions.",
                                mitre_technique="T1195.002",
                                owasp_category="CICD-SEC-3",
                                file_path=file_path,
                            ))
                            break

        return findings