from typing import Any

from .base import BaseRule, Finding, Severity


class CachePoisoningRule(BaseRule):
    rule_id = "FS031"
    title = "Cache Poisoning Risk — Cache Used With Privileged Trigger"
    severity = Severity.HIGH

    # Triggers that run with base-branch permissions but can be influenced by
    # untrusted code, so a cache entry written there can be attacker-controlled.
    RISKY_TRIGGERS = ("pull_request_target", "workflow_run")

    def _extract_triggers(self, config: dict[Any, Any]) -> list[str]:
        triggers = config.get(True, {})  # PyYAML converts 'on' to True
        if isinstance(triggers, dict):
            return [t for t in triggers if isinstance(t, str)]
        if isinstance(triggers, list):
            return [t for t in triggers if isinstance(t, str)]
        return []

    def check(self, config: dict[Any, Any], file_path: str, platform: str = "github") -> list[Finding]:
        if platform != "github":
            return []
        findings: list[Finding] = []

        triggers = self._extract_triggers(config)
        if not any(t in triggers for t in self.RISKY_TRIGGERS):
            return findings

        jobs = config.get("jobs", {})
        if not isinstance(jobs, dict):
            return findings
        for job in jobs.values():
            if not isinstance(job, dict):
                continue
            for step in job.get("steps", []):
                if isinstance(step, dict) and step.get("uses", "").startswith("actions/cache"):
                    findings.append(Finding(
                        rule_id=self.rule_id,
                        title=self.title,
                        severity=self.severity,
                        description="This workflow uses actions/cache in a workflow triggered by pull_request_target or workflow_run. Those triggers can be influenced by untrusted forks, so an attacker can poison a cache entry that is later restored into a privileged run, achieving code execution with repository secrets.",
                        remediation="Do not read or write caches in workflows triggered by pull_request_target or workflow_run. Restrict caching to trusted triggers (push to protected branches), or scope cache keys so untrusted contexts can never overwrite a trusted entry.",
                        mitre_technique="T1195.001",
                        owasp_category="CICD-SEC-3",
                        file_path=file_path,
                    ))
        return findings
