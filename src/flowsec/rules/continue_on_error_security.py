from typing import Any

from .base import BaseRule, Finding, Severity


class ContinueOnErrorSecurityRule(BaseRule):
    rule_id = "FS017"
    title = "Security Scan Silenced — Failures Suppressed with continue-on-error"
    severity = Severity.MEDIUM

    SECURITY_KEYWORDS = [
        "scan", "audit", "trivy", "snyk", "bandit", "semgrep",
        "sonarqube", "sonar", "safety", "checkov", "grype", "syft",
        "gitleaks", "trufflehog", "owasp", "zap", "nuclei",
        "dependency-check", "dependencycheck", "veracode", "fortify",
    ]

    def _is_security_related(self, *texts: str) -> bool:
        combined = " ".join(texts).lower()
        return any(kw in combined for kw in self.SECURITY_KEYWORDS)

    def check(self, config: dict[Any, Any], file_path: str, platform: str = "github") -> list[Finding]:
        findings: list[Finding] = []

        if platform == "github":
            jobs = config.get("jobs", {})
            if not isinstance(jobs, dict):
                return findings
            for job in jobs.values():
                if not isinstance(job, dict):
                    continue
                for step in job.get("steps", []):
                    if not isinstance(step, dict):
                        continue
                    if step.get("continue-on-error") is not True:
                        continue
                    name = step.get("name", "")
                    uses = step.get("uses", "")
                    run = step.get("run", "")
                    if self._is_security_related(name, uses, run):
                        findings.append(Finding(
                            rule_id=self.rule_id,
                            title=self.title,
                            severity=self.severity,
                            description=f"Security-related step '{name or uses or 'unnamed'}' has 'continue-on-error: true'. Vulnerabilities detected by this scanner will not block the pipeline, meaning the team receives no signal and vulnerable code can be merged and deployed.",
                            remediation="Remove 'continue-on-error: true' from security scanning steps. If the scanner produces too many findings, use the tool's own severity threshold flags (e.g. '--exit-code 1 --severity CRITICAL') to control what constitutes a blocking failure rather than suppressing all failures at the pipeline level.",
                            mitre_technique="T1562.001",
                            owasp_category="CICD-SEC-7",
                            file_path=file_path,
                        ))

        elif platform == "gitlab":
            for key, value in config.items():
                if key.startswith("__line_") or not isinstance(value, dict):
                    continue
                if value.get("allow_failure") is not True:
                    continue
                if self._is_security_related(key):
                    findings.append(Finding(
                        rule_id=self.rule_id,
                        title=self.title,
                        severity=self.severity,
                        description=f"GitLab CI job '{key}' appears to be a security scan but has 'allow_failure: true'. This means the job will never cause a pipeline to fail, silently hiding vulnerabilities from the team.",
                        remediation="Remove 'allow_failure: true' from security scan jobs. Configure the scanner's built-in severity thresholds to control what constitutes a blocking failure.",
                        mitre_technique="T1562.001",
                        owasp_category="CICD-SEC-7",
                        file_path=file_path,
                    ))

        elif platform == "azure":
            for key, value in config.items():
                if key.startswith("__line_") or not isinstance(value, dict):
                    continue
                for step in value.get("steps", []):
                    if not isinstance(step, dict):
                        continue
                    if step.get("continueOnError") is not True:
                        continue
                    display_name = step.get("displayName", "")
                    task = step.get("task", "")
                    if self._is_security_related(display_name, task):
                        findings.append(Finding(
                            rule_id=self.rule_id,
                            title=self.title,
                            severity=self.severity,
                            description=f"Azure DevOps step '{display_name or task}' appears to be a security scan but has 'continueOnError: true'. Failures from this step are silently swallowed and will not block the pipeline.",
                            remediation="Remove 'continueOnError: true' from security scanning tasks. Use the tool's own failure threshold configuration to control blocking behavior.",
                            mitre_technique="T1562.001",
                            owasp_category="CICD-SEC-7",
                            file_path=file_path,
                        ))

        return findings
