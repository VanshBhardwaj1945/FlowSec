from typing import Any

from .base import BaseRule, Finding, Severity, numbered_lines, pipeline_commands


class DockerSocketMountRule(BaseRule):
    rule_id = "FS027"
    title = "Docker Socket Mounted — Full Host Control from Pipeline"
    severity = Severity.CRITICAL

    def _get_commands(self, config: dict[Any, Any], platform: str) -> list[str]:
        return pipeline_commands(config, platform)

    def check(self, config: dict[Any, Any], file_path: str, platform: str = "github") -> list[Finding]:
        findings: list[Finding] = []
        for command in self._get_commands(config, platform):
            for line_no, line in numbered_lines(command):
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
                        line_number=line_no,
                    ))
        return findings
