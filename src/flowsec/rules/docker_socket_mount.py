from typing import Any

from .base import BaseRule, Finding, Severity


class DockerSocketMountRule(BaseRule):
    rule_id = "FS027"
    title = "Docker Socket Mounted — Full Host Control from Pipeline"
    severity = Severity.CRITICAL

    def _get_commands(self, config: dict[Any, Any], platform: str) -> list[str]:
        commands: list[str] = []
        if platform == "github":
            jobs = config.get("jobs", {})
            if not isinstance(jobs, dict):
                return commands
            for job in jobs.values():
                if not isinstance(job, dict):
                    continue
                for step in job.get("steps", []):
                    if isinstance(step, dict) and step.get("run"):
                        commands.append(step["run"])
        elif platform in ("gitlab", "azure"):
            for value in config.values():
                if not isinstance(value, dict):
                    continue
                scripts = value.get("script", [])
                if isinstance(scripts, str):
                    scripts = [scripts]
                if isinstance(scripts, list):
                    commands.extend([s for s in scripts if isinstance(s, str)])
        return commands

    def check(self, config: dict[Any, Any], file_path: str, platform: str = "github") -> list[Finding]:
        findings: list[Finding] = []
        for command in self._get_commands(config, platform):
            for line in command.split("\n"):
                if "/var/run/docker.sock" in line:
                    findings.append(Finding(
                        rule_id=self.rule_id,
                        title=self.title,
                        severity=self.severity,
                        description=f"The Docker socket is mounted into a container: '{line.strip()}'. Any process with access to /var/run/docker.sock can start privileged containers, read other containers' data, and take full control of the runner host — this is equivalent to root on the host, even without the --privileged flag.",
                        remediation="Do not mount /var/run/docker.sock into pipeline containers. If you need to build images, use a rootless builder like BuildKit/buildah or a dedicated build service instead of exposing the host Docker daemon.",
                        mitre_technique="T1611",
                        owasp_category="CICD-SEC-7",
                        file_path=file_path,
                    ))
        return findings
