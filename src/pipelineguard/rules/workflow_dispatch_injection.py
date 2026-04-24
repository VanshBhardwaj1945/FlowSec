from typing import Any
from .base import BaseRule, Finding, Severity

class WorkflowDispatchInjectionRule(BaseRule):
    rule_id = "FS013"
    title = "Workflow Dispatch Injection — Unvalidated Input Used in Shell Command"
    severity = Severity.CRITICAL

    def check(self, config: dict[str, Any], file_path: str, platform: str = "github") -> list[Finding]:
        if platform != "github":
            return []
        findings = []
        triggers = config.get(True, {})

        if not triggers:
            return findings

        trigger_list = list(triggers.keys()) if isinstance(triggers, dict) else triggers
        if "workflow_dispatch" not in trigger_list:
            return findings

        jobs = config.get("jobs", {})
        for job in jobs.values():
            for step in job.get("steps", []):
                run = step.get("run", "")
                if not run:
                    continue
                for line in run.split("\n"):
                    if "${{ inputs." in line:
                        import re
                        unquoted = re.search(r'(?<!")\$\{\{\s*inputs\.\w+\s*\}\}(?!")', line)
                        if unquoted:
                            findings.append(Finding(
                                rule_id=self.rule_id,
                                title=self.title,
                                severity=self.severity,
                                description=f"Workflow dispatch input is used directly in a shell command without quotes: '{line.strip()}'. An attacker with access to trigger this workflow can inject arbitrary shell commands through the input field.",
                                remediation="Always wrap workflow dispatch inputs in double quotes when used in shell commands: \"${{ inputs.environment }}\" instead of ${{ inputs.environment }}. Consider validating inputs against an allowlist before use.",
                                mitre_technique="T1059",
                                owasp_category="CICD-SEC-9",
                                file_path=file_path,
                            ))

        return findings