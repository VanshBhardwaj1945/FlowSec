from typing import Any

from .base import BaseRule, Finding, Severity


class GitHubScriptInjectionRule(BaseRule):
    rule_id = "FS029"
    title = "github-script Injection — Untrusted Event Data in Inline Script"
    severity = Severity.CRITICAL

    # Same attacker-controlled context values as FS011, but here they are dangerous
    # inside the 'script:' input of actions/github-script rather than a run: step.
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

    def check(self, config: dict[Any, Any], file_path: str, platform: str = "github") -> list[Finding]:
        if platform != "github":
            return []
        findings: list[Finding] = []
        jobs = config.get("jobs", {})
        if not isinstance(jobs, dict):
            return findings
        for job in jobs.values():
            if not isinstance(job, dict):
                continue
            for step in job.get("steps", []):
                if not isinstance(step, dict):
                    continue
                if not step.get("uses", "").startswith("actions/github-script"):
                    continue
                script = (step.get("with", {}) or {}).get("script", "")
                if not isinstance(script, str):
                    continue
                for ctx in self.DANGEROUS_CONTEXTS:
                    if f"${{{{ {ctx}" in script:
                        findings.append(Finding(
                            rule_id=self.rule_id,
                            title=self.title,
                            severity=self.severity,
                            description=f"Untrusted GitHub context '${{{{ {ctx} }}}}' is interpolated into an actions/github-script 'script:' block. The expression is substituted before the JavaScript is parsed, so an attacker controlling this value can inject arbitrary JavaScript that runs with the workflow's token.",
                            remediation=f"Pass the value in through the step 'env:' block and read it with 'process.env' inside the script, e.g. env: TITLE: ${{{{ {ctx} }}}} then use process.env.TITLE. Never interpolate event data directly into the script body.",
                            mitre_technique="T1059.004",
                            owasp_category="CICD-SEC-4",
                            file_path=file_path,
                        ))
                        break
        return findings
