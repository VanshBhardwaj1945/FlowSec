from typing import Any
from .base import BaseRule, Finding, Severity


class HardcodedSecretsRule(BaseRule):
    rule_id = "FS001"
    title = "Hardcoded Secret — Plaintext Credential in Workflow"
    severity = Severity.CRITICAL #
    
    SUSPICIOUS_PATTERNS = [
    "api_key", "apikey", "api_token", "access_token",
    "secret", "password", "passwd", "token",
    "private_key", "client_secret", "auth_token",
    "subscription_id", "account_key", "login", "private"
    ]

    def _extract_env_vars(self, config: dict[str, Any]) -> dict[str, str]:
        env_vars = {}
        jobs = config.get("jobs", {})
        for job in jobs.values():
            env_vars.update({
                k: v for k, v in job.get("env", {}).items()
                if not k.startswith("__line_")
            })
            for step in job.get("steps", []):
                env_vars.update({
                    k: v for k, v in step.get("env", {}).items()
                    if not k.startswith("__line_")
                })
        return env_vars

    def check(self, config: dict[str, Any], file_path: str) -> list[Finding]:
        findings = []
        jobs = config.get("jobs", {})

        for job in jobs.values():
            all_envs = [job.get("env", {})]
            for step in job.get("steps", []):
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
                                file_path=file_path,
                                line_number=env.get(f"__line_{var_name}__", 0),
                            ))

        return findings