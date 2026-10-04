from typing import Any

from .base import BaseRule, Finding, Severity, numbered_lines, pipeline_commands


class ContainerRunsAsRootRule(BaseRule):
    rule_id = "FS020"
    title = "Container Running as Root — Elevated Privilege in Pipeline"
    severity = Severity.HIGH

    def _get_commands(self, config: dict[Any, Any], platform: str) -> list[str]:
        return pipeline_commands(config, platform)

    def check(self, config: dict[Any, Any], file_path: str, platform: str = "github") -> list[Finding]:
        findings: list[Finding] = []
        commands = self._get_commands(config, platform)

        for command in commands:
            for line_no, line in numbered_lines(command):
                line = line.strip()
                if "docker run" in line:
                    if "--user" not in line or "--user root" in line or "--user=root" in line:
                        findings.append(Finding(
                            rule_id=self.rule_id,
                            title=self.title,
                            severity=self.severity,
                            description=f"Docker container is run without a non-root user: '{line.strip()}'. Containers running as root have elevated privileges that can be exploited if the container is compromised.",
                            remediation="Add '--user 1000:1000' or '--user nobody' to your docker run command to run the container as a non-root user.",
                            mitre_technique="T1611",
                            owasp_category="CICD-SEC-7",
                            file_path=file_path,
                            line_number=line_no,
                        ))
                        break
        return findings