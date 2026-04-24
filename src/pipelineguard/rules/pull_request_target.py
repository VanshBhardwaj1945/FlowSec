from typing import Any
from .base import BaseRule, Finding, Severity


class PullRequestTargetRule(BaseRule):
    rule_id = "FS005"
    title = "Pull Request Target — Secrets Exposed to Fork Code"
    severity = Severity.CRITICAL

    def _extract_triggers(self, config: dict[str, Any]) -> list[str]:
        triggers = config.get(True, {})  # PyYAML converts 'on' to True
        if isinstance(triggers, dict):
            return list(triggers.keys())
        if isinstance(triggers, list):
            return triggers
        return []

    def _extract_uses(self, config: dict[str, Any]) -> list[str]:
        uses = []
        jobs = config.get("jobs", {})
        for job in jobs.values():
            for step in job.get("steps", []):
                if "uses" in step:
                    uses.append(step["uses"])
        return uses

    def check(self, config: dict[str, Any], file_path: str, platform: str = "github") -> list[Finding]:
        if platform != "github":
            return [] 
        findings = []
        triggers = self._extract_triggers(config)
        uses = self._extract_uses(config)

        if "pull_request_target" not in triggers:
            return findings

        # pull_request_target is dangerous when combined with
        # checking out untrusted code from the PR
        dangerous_actions = [
            "actions/checkout",
        ]

        for use in uses:
            if any(action in use for action in dangerous_actions):
                findings.append(Finding(
                    rule_id=self.rule_id,
                    title=self.title,
                    severity=self.severity,
                    description="This workflow uses 'pull_request_target' and checks out code from the pull request. 'pull_request_target' runs in the context of the base branch with access to secrets — combined with checking out PR code, an attacker can submit a malicious PR that executes arbitrary code with access to your repository secrets.",
                    remediation="Do not combine pull_request_target with actions/checkout of the PR head. If you need to run code from a PR, use the pull_request event instead which does not have access to secrets. If pull_request_target is required, never check out or execute code from the PR branch.",
                    mitre_technique="T1611",
                    file_path=file_path,
                    owasp_category="CICD-SEC-4",

                ))
                break

        return findings