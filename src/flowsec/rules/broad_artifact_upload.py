from typing import Any

from .base import BaseRule, Finding, Severity


class BroadArtifactUploadRule(BaseRule):
    rule_id = "FS022"
    title = "Broad Artifact Upload — Entire Workspace Exposed as Artifact"
    severity = Severity.MEDIUM

    DANGEROUS_PATHS = {".", "*", "**", "./", "**/", "$(System.DefaultWorkingDirectory)"}

    def _make_finding(self, path: str, file_path: str) -> Finding:
        return Finding(
            rule_id=self.rule_id,
            title=self.title,
            severity=self.severity,
            description=f"Artifact upload path '{path}' captures the entire workspace. Pipeline runs often write sensitive data to disk: temporary credentials, .env files, tool caches containing tokens, and private keys. Uploading the full workspace makes all of this available to anyone who can download the artifact.",
            remediation="Specify an explicit output directory (e.g. 'dist/', 'build/', 'target/') that contains only intentional build outputs. Add a .artifactignore or equivalent to exclude sensitive files, and ensure credentials are never written to the workspace in plaintext.",
            mitre_technique="T1560",
            owasp_category="CICD-SEC-9",
            file_path=file_path,
        )

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
                    if "actions/upload-artifact" not in step.get("uses", ""):
                        continue
                    with_params = step.get("with", {}) or {}
                    path = with_params.get("path", "")
                    if isinstance(path, str) and path.strip() in self.DANGEROUS_PATHS:
                        findings.append(self._make_finding(path.strip(), file_path))

        elif platform == "gitlab":
            for key, value in config.items():
                if key.startswith("__line_") or not isinstance(value, dict):
                    continue
                artifacts = value.get("artifacts", {})
                if not isinstance(artifacts, dict):
                    continue
                paths = artifacts.get("paths", [])
                if isinstance(paths, list):
                    for p in paths:
                        if isinstance(p, str) and p.strip() in self.DANGEROUS_PATHS:
                            findings.append(self._make_finding(p.strip(), file_path))

        elif platform == "azure":
            for key, value in config.items():
                if key.startswith("__line_") or not isinstance(value, dict):
                    continue
                for step in value.get("steps", []):
                    if not isinstance(step, dict):
                        continue
                    task = step.get("task", "")
                    if "PublishBuildArtifacts" not in task and "PublishPipelineArtifact" not in task:
                        continue
                    inputs = step.get("inputs", {}) or {}
                    path = inputs.get("PathtoPublish", inputs.get("targetPath", ""))
                    if isinstance(path, str) and path.strip() in self.DANGEROUS_PATHS:
                        findings.append(self._make_finding(path.strip(), file_path))

        return findings
