from typing import Any
from .base import BaseRule, Finding, Severity


class WorkflowRunTriggerRule(BaseRule):
    rule_id = "FS016"
    title = "workflow_run Trigger — Privileged Execution from Untrusted Workflow"
    severity = Severity.HIGH

    def check(self, config: dict[str, Any], file_path: str, platform: str = "github") -> list[Finding]:
        if platform != "github":
            return []
        triggers = config.get(True, {})  # PyYAML parses 'on' as True
        if not isinstance(triggers, dict):
            return []
        if "workflow_run" not in triggers:
            return []

        return [Finding(
            rule_id=self.rule_id,
            title=self.title,
            severity=self.severity,
            description="This workflow uses the 'workflow_run' trigger. Like 'pull_request_target', workflows triggered by 'workflow_run' execute in the context of the base branch with full access to repository secrets, even when the triggering workflow originated from a fork. An attacker who controls the triggering workflow can abuse this to exfiltrate secrets or gain write access to the repository.",
            remediation="Treat 'workflow_run' with the same caution as 'pull_request_target'. Never checkout or execute code from the triggering run's artifacts without explicit validation. Restrict to same-repo triggers by checking: 'if: github.event.workflow_run.head_repository.full_name == github.repository'. Prefer the 'pull_request' trigger for code from forks — it does not have secret access.",
            mitre_technique="T1059",
            owasp_category="CICD-SEC-1",
            file_path=file_path,
        )]
