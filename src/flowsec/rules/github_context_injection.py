from typing import Any
from .base import BaseRule, Finding, Severity


class GitHubContextInjectionRule(BaseRule):
    rule_id = "FS011"
    title = "GitHub Context Injection — Untrusted Event Data in Run Step"
    severity = Severity.CRITICAL

    # These context values are attacker-controlled and unsafe to use directly in run: steps.
    # GitHub substitutes them before the shell sees the command, bypassing all quoting.
    DANGEROUS_CONTEXTS = [
        "github.event.issue.title",
        "github.event.issue.body",
        "github.event.pull_request.title",
        "github.event.pull_request.body",
        "github.event.pull_request.head.ref",
        "github.event.pull_request.head.label",
        "github.event.comment.body",
        "github.event.review.body",
        "github.event.discussion.title",
        "github.event.discussion.body",
        "github.head_ref",
    ]

    def check(self, config: dict[str, Any], file_path: str, platform: str = "github") -> list[Finding]:
        if platform != "github":
            return []
        findings = []
        jobs = config.get("jobs", {})
        if not isinstance(jobs, dict):
            return findings
        for job in jobs.values():
            if not isinstance(job, dict):
                continue
            for step in job.get("steps", []):
                if not isinstance(step, dict):
                    continue
                run = step.get("run", "")
                if not run:
                    continue
                for ctx in self.DANGEROUS_CONTEXTS:
                    if f"${{{{ {ctx}" in run:
                        findings.append(Finding(
                            rule_id=self.rule_id,
                            title=self.title,
                            severity=self.severity,
                            description=f"Untrusted GitHub context expression '${{{{ {ctx} }}}}' is used directly in a run step. GitHub substitutes this value before the shell parses the command, so quoting provides no protection — an attacker controlling this value can inject arbitrary shell commands.",
                            remediation=f"Pass the value through an environment variable instead: add 'env: SAFE_VAR: ${{{{ {ctx} }}}}' to the step, then reference '$SAFE_VAR' in the shell script. The shell receives it as a safe variable, not an interpolated string.",
                            mitre_technique="T1059.004",
                            owasp_category="CICD-SEC-4",
                            file_path=file_path,
                        ))
                        break  # one finding per step
        return findings
