from typing import Any
from .base import BaseRule, Finding, Severity


class HardcodedSecretsRule(BaseRule):
    rule_id = "FS001"
    title = "Hardcoded Secret — Plaintext Credential in Workflow"
    severity = Severity.CRITICAL

    SUSPICIOUS_PATTERNS = [
        "api_key", "apikey", "api_token", "access_token",
        "secret", "password", "passwd", "token",
        "private_key", "client_secret", "auth_token",
        "subscription_id", "account_key", "login", "private"
    ]

    def _extract_github_env_vars(self, config: dict[str, Any]) -> dict[str, Any]:
        env_vars = {}
        jobs = config.get("jobs", {})
        for job in jobs.values():
            if not isinstance(job, dict):
                continue
            env_vars.update({
                k: v for k, v in job.get("env", {}).items()
                if not k.startswith("__line_")
            })
            for step in job.get("steps", []):
                if not isinstance(step, dict):
                    continue
                env_vars.update({
                    k: v for k, v in step.get("env", {}).items()
                    if not k.startswith("__line_")
                })
        return env_vars

    def _extract_gitlab_variables(self, config: dict[str, Any]) -> dict[str, Any]:
        variables = {}
        top_level = config.get("variables", {})
        if isinstance(top_level, dict):
            variables.update({
                k: v for k, v in top_level.items()
                if not k.startswith("__line_")
            })
        for key, value in config.items():
            if isinstance(value, dict) and "script" in value:
                job_vars = value.get("variables", {})
                if isinstance(job_vars, dict):
                    variables.update({
                        k: v for k, v in job_vars.items()
                        if not k.startswith("__line_")
                    })
        return variables

    def _extract_azure_variables(self, config: dict[str, Any]) -> dict[str, Any]:
        variables = {}
        top_level = config.get("variables", {})
        if isinstance(top_level, dict):
            variables.update({
                k: v for k, v in top_level.items()
                if not k.startswith("__line_")
            })
        return variables

    def check(self, config: dict[str, Any], file_path: str, platform: str = "github") -> list[Finding]:
        findings = []

        if platform == "github":
            jobs = config.get("jobs", {})
            for job in jobs.values():
                if not isinstance(job, dict):
                    continue
                all_envs = [job.get("env", {})]
                for step in job.get("steps", []):
                    if isinstance(step, dict):
                        all_envs.append(step.get("env", {}))
                for env in all_envs:
                    for var_name, var_value in env.items():
                        if var_name.startswith("__line_"):
                            continue
                        if not isinstance(var_value, str):
                            continue
                        if any(pattern in var_name.lower() for pattern in self.SUSPICIOUS_PATTERNS):
                            if not var_value.startswith("${{"):
                                findings.append(Finding(
                                    rule_id=self.rule_id,
                                    title=self.title,
                                    severity=self.severity,
                                    description=f"Hardcoded secret found in environment variable '{var_name}'",
                                    remediation=f"Move '{var_name}' to GitHub Secrets and reference it as ${{{{ secrets.{var_name} }}}}",
                                    mitre_technique="T1552.001",
                                    owasp_category="CICD-SEC-6",
                                    file_path=file_path,
                                    line_number=env.get(f"__line_{var_name}__", 0),
                                ))

        elif platform in ("gitlab", "azure"):
            if platform == "gitlab":
                env_vars = self._extract_gitlab_variables(config)
            else:
                env_vars = self._extract_azure_variables(config)

            for var_name, var_value in env_vars.items():
                if not isinstance(var_value, str):
                    continue
                if any(pattern in var_name.lower() for pattern in self.SUSPICIOUS_PATTERNS):
                    safe_prefixes = ("${{", "${", "$CI_", "$AZURE_")
                    if not any(var_value.startswith(p) for p in safe_prefixes):
                        findings.append(Finding(
                            rule_id=self.rule_id,
                            title=self.title,
                            severity=self.severity,
                            description=f"Hardcoded secret found in variable '{var_name}'",
                            remediation=f"Move '{var_name}' to your platform's secret manager and reference it as an environment variable.",
                            mitre_technique="T1552.001",
                            owasp_category="CICD-SEC-6",
                            file_path=file_path,
                        ))

        return findings