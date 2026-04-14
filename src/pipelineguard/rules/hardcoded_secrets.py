from typing import Any
from .base import BaseRule, Finding, Severity


class HardcodedSecretsRule(BaseRule):
    rule_id = "FS001"
    title = "Hardcoded Secrets - API Keys, Passwords, Tokens"
    severity = Severity.CRITICAL #
    
    SUSPICIOUS_PATTERNS = [
    "api_key", "apikey", "api_token", "access_token",
    "secret", "password", "passwd", "token",
    "private_key", "client_secret", "auth_token",
    "subscription_id", "account_key", "login", "private"
    ]

    def _extract_env_vars(self, config: dict[str, Any]) -> dict[str, str]:
        env_vars = {}                                   # Creating list of ENV Variable
        jobs = config.get("jobs", {})                   # jobs is set too whats inside {} for jobs
        for job in jobs.values():                       # iterate through job.values (but vlaues isnt set to antthing)
            env_vars.update(job.get("env", {}))         # update env_vars and add whats in env
            for step in job.get("steps", []):
                env_vars.update(step.get("env", {}))
        return env_vars

    def check(self, config: dict[str, Any], file_path: str) -> list[Finding]:
        findings = []
        env_vars = self._extract_env_vars(config)

        for var_name, var_value in env_vars.items():
            if any(pattern in var_name.lower() for pattern in self.SUSPICIOUS_PATTERNS):
                if not (var_value.startswith("${{")):
                    findings.append(Finding( 
                        rule_id=self.rule_id,
                        title=self.title,
                        severity=self.severity,
                        description=f"Hardcoded secret found in environment variable '{var_name}'",
                        remediation=f"Move '{var_name}' to GitHub Secrets and reference it as ${{{{ secrets.{var_name} }}}}",
                        mitre_technique="T1552.001",
                        file_path=file_path,
                ))
        return findings
 