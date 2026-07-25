from typing import Any
from .base import BaseRule, Finding, Severity

DEPLOY_KEYWORDS = ["deploy", "release", "publish", "prod", "production", "ship"]


class DeployAllBranchesRule(BaseRule):
    rule_id = "FS026"
    title = "Unguarded Deploy — Deployment Job Runs on Untrusted Branches"
    severity = Severity.HIGH

    def _has_broad_github_trigger(self, config: dict[str, Any]) -> bool:
        triggers = config.get(True, {})
        if not isinstance(triggers, dict):
            return False
        # pull_request trigger always means untrusted code can reach the job
        if "pull_request" in triggers:
            return True
        # push with no branch filter means all branches
        push_cfg = triggers.get("push", {})
        if push_cfg is None or push_cfg == {}:
            return True
        if isinstance(push_cfg, dict) and push_cfg.get("branches") is None:
            return True
        return False

    def check(self, config: dict[str, Any], file_path: str, platform: str = "github") -> list[Finding]:
        findings = []

        if platform == "github":
            if not self._has_broad_github_trigger(config):
                return []
            jobs = config.get("jobs", {})
            if not isinstance(jobs, dict):
                return []
            for job_name, job in jobs.items():
                if not isinstance(job, dict):
                    continue
                if not any(kw in job_name.lower() for kw in DEPLOY_KEYWORDS):
                    continue
                # Safe if the job has an if: condition referencing github.ref or event_name
                job_if = str(job.get("if", ""))
                if "github.ref" in job_if or "github.event_name" in job_if:
                    continue
                findings.append(Finding(
                    rule_id=self.rule_id,
                    title=self.title,
                    severity=self.severity,
                    description=f"Job '{job_name}' appears to be a deployment job but has no branch guard and the workflow is triggered on pull requests or all branches. Any contributor opening a PR or pushing to any branch can trigger a production deployment.",
                    remediation="Add an 'if:' condition to the job: 'if: github.ref == \"refs/heads/main\" && github.event_name == \"push\"'. This ensures deployments only run on direct pushes to the main branch, not on PRs or feature branches.",
                    mitre_technique="T1078",
                    owasp_category="CICD-SEC-1",
                    file_path=file_path,
                ))

        elif platform == "gitlab":
            for key, value in config.items():
                if key.startswith("__line_") or not isinstance(value, dict):
                    continue
                if not any(kw in key.lower() for kw in DEPLOY_KEYWORDS):
                    continue
                # Safe if job has 'only', 'except', or 'rules' restricting branch
                if value.get("only") is not None or value.get("rules") is not None:
                    continue
                findings.append(Finding(
                    rule_id=self.rule_id,
                    title=self.title,
                    severity=self.severity,
                    description=f"GitLab CI job '{key}' appears to be a deployment job with no branch restriction. Without 'only:' or 'rules:', it will trigger on every pipeline regardless of branch, including merge request pipelines and feature branches.",
                    remediation="Add 'only: - main' or a 'rules:' block to restrict the job: 'rules: - if: $CI_COMMIT_BRANCH == \"main\"'. This ensures the deployment only runs on the protected main branch.",
                    mitre_technique="T1078",
                    owasp_category="CICD-SEC-1",
                    file_path=file_path,
                ))

        elif platform == "azure":
            for key, value in config.items():
                if key.startswith("__line_") or not isinstance(value, dict):
                    continue
                if not any(kw in key.lower() for kw in DEPLOY_KEYWORDS):
                    continue
                # Safe if a condition referencing SourceBranch is present
                condition = str(value.get("condition", ""))
                if "SourceBranch" in condition or "Build.Reason" in condition:
                    continue
                if value.get("condition") is None:
                    findings.append(Finding(
                        rule_id=self.rule_id,
                        title=self.title,
                        severity=self.severity,
                        description=f"Azure DevOps job/stage '{key}' appears to be a deployment stage with no branch condition. Without a condition, it will run on all branches and PR builds, not just the main branch.",
                        remediation="Add a condition to restrict deployment: 'condition: and(succeeded(), eq(variables[\"Build.SourceBranch\"], \"refs/heads/main\"))'. This prevents deployments from feature branches and PR builds.",
                        mitre_technique="T1078",
                        owasp_category="CICD-SEC-1",
                        file_path=file_path,
                    ))

        return findings
