from typing import Any

from .base import BaseRule, Finding, Severity


class GitHubEnvInjectionRule(BaseRule):
    rule_id = "FS035"
    title = "Environment File Injection — Untrusted Data Written to GITHUB_ENV"
    severity = Severity.HIGH

    ENV_FILES = ("$GITHUB_ENV", "${GITHUB_ENV}", "$GITHUB_PATH", "${GITHUB_PATH}")
    DANGEROUS_CONTEXTS = ("github.event.", "github.head_ref")

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
                run = step.get("run", "")
                if not isinstance(run, str) or not run:
                    continue
                for line in run.split("\n"):
                    writes_env = any(env_file in line for env_file in self.ENV_FILES)
                    has_untrusted = any(f"${{{{ {ctx}" in line for ctx in self.DANGEROUS_CONTEXTS)
                    if writes_env and has_untrusted:
                        findings.append(Finding(
                            rule_id=self.rule_id,
                            title=self.title,
                            severity=self.severity,
                            description=f"Untrusted event data is written to a GitHub environment file: '{line.strip()}'. A value the attacker controls becomes an environment variable or PATH entry for every later step — a newline in the value can even define additional variables, leading to command execution.",
                            remediation="Never write untrusted context values to $GITHUB_ENV or $GITHUB_PATH. Pass the value through the step 'env:' block, validate it, and only then write a known-safe value.",
                            mitre_technique="T1059.004",
                            owasp_category="CICD-SEC-4",
                            file_path=file_path,
                        ))
                        break
        return findings
