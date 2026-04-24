from typing import Any
from .base import BaseRule, Finding, Severity


class SelfHostedRunnerRule(BaseRule):
    rule_id = "FS007"
    title = "Self-Hosted Runner — Persistent Environment Risk"
    severity = Severity.HIGH

    def check(self, config: dict[str, Any], file_path: str, platform: str = "github") -> list[Finding]:
        findings = []

        if platform == "github":
            jobs = config.get("jobs", {})
            for job_name, job in jobs.items():
                if not isinstance(job, dict):
                    continue
                runs_on = job.get("runs-on", "")
                if isinstance(runs_on, list):
                    runs_on_str = " ".join(runs_on).lower()
                else:
                    runs_on_str = str(runs_on).lower()
                if "self-hosted" in runs_on_str:
                    findings.append(Finding(
                        rule_id=self.rule_id,
                        title=self.title,
                        severity=self.severity,
                        description=f"Job '{job_name}' runs on a self-hosted runner. Self-hosted runners persist between jobs and are not automatically cleaned up.",
                        remediation="Use ephemeral containerized runners or configure the runner to reset to a clean state after every job.",
                        mitre_technique="T1053",
                        owasp_category="CICD-SEC-7",
                        file_path=file_path,
                    ))

        elif platform == "gitlab":
            for key, value in config.items():
                if not isinstance(value, dict):
                    continue
                if "script" not in value:
                    continue
                tags = value.get("tags", [])
                if isinstance(tags, list):
                    tags_str = " ".join(tags).lower()
                else:
                    tags_str = str(tags).lower()
                if "self-hosted" in tags_str or "self_hosted" in tags_str:
                    findings.append(Finding(
                        rule_id=self.rule_id,
                        title=self.title,
                        severity=self.severity,
                        description=f"GitLab job '{key}' uses a self-hosted runner via tags. Self-hosted runners persist between jobs.",
                        remediation="Use ephemeral containerized runners or configure the runner to reset after every job.",
                        mitre_technique="T1053",
                        owasp_category="CICD-SEC-7",
                        file_path=file_path,
                    ))

        elif platform == "azure":
            jobs = config.get("jobs", [])
            if isinstance(jobs, list):
                for job in jobs:
                    if not isinstance(job, dict):
                        continue
                    pool = job.get("pool", {})
                    if isinstance(pool, dict):
                        name = pool.get("name", "").lower()
                        if name and "azure pipelines" not in name:
                            findings.append(Finding(
                                rule_id=self.rule_id,
                                title=self.title,
                                severity=self.severity,
                                description=f"Azure DevOps job uses a self-hosted agent pool '{pool.get('name')}'. Self-hosted agents persist between jobs.",
                                remediation="Use Microsoft-hosted agents where possible or configure self-hosted agents to reset after every job.",
                                mitre_technique="T1053",
                                owasp_category="CICD-SEC-7",
                                file_path=file_path,
                            ))

        return findings