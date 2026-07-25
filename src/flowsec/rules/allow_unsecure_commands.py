from typing import Any

from .base import BaseRule, Finding, Severity


class AllowUnsecureCommandsRule(BaseRule):
    rule_id = "FS033"
    title = "Unsecure Commands Enabled — Deprecated set-env Injection Re-Enabled"
    severity = Severity.HIGH

    def _collect_env_blocks(self, config: dict[Any, Any]) -> list[dict[Any, Any]]:
        blocks: list[dict[Any, Any]] = []
        top_env = config.get("env")
        if isinstance(top_env, dict):
            blocks.append(top_env)
        jobs = config.get("jobs", {})
        if isinstance(jobs, dict):
            for job in jobs.values():
                if not isinstance(job, dict):
                    continue
                if isinstance(job.get("env"), dict):
                    blocks.append(job["env"])
                for step in job.get("steps", []):
                    if isinstance(step, dict) and isinstance(step.get("env"), dict):
                        blocks.append(step["env"])
        return blocks

    def check(self, config: dict[Any, Any], file_path: str, platform: str = "github") -> list[Finding]:
        if platform != "github":
            return []
        findings: list[Finding] = []
        for env in self._collect_env_blocks(config):
            value = env.get("ACTIONS_ALLOW_UNSECURE_COMMANDS")
            if value is not None and str(value).lower() == "true":
                findings.append(Finding(
                    rule_id=self.rule_id,
                    title=self.title,
                    severity=self.severity,
                    description="ACTIONS_ALLOW_UNSECURE_COMMANDS is set to true. This re-enables the deprecated set-env and add-path workflow commands, which let any string written to stdout modify environment variables and PATH for later steps — a well-known command injection vector GitHub disabled by default.",
                    remediation="Remove ACTIONS_ALLOW_UNSECURE_COMMANDS. Migrate any action or script that relied on the old set-env/add-path commands to the environment files $GITHUB_ENV and $GITHUB_PATH.",
                    mitre_technique="T1059.004",
                    owasp_category="CICD-SEC-4",
                    file_path=file_path,
                ))
        return findings
