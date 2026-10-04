from typing import Any

from .base import BaseRule, Finding, Severity, numbered_lines, pipeline_commands


class PrivilegedDockerRule(BaseRule):
    rule_id = "FS024"
    title = "Privileged Docker Container — Full Host Access Granted in Pipeline"
    severity = Severity.CRITICAL

    PRIVILEGED_FLAGS = [
        "--privileged",
        "--cap-add SYS_ADMIN",
        "--cap-add=SYS_ADMIN",
        "--cap-add NET_ADMIN",
        "--cap-add=NET_ADMIN",
        "--security-opt seccomp=unconfined",
        "--security-opt=seccomp=unconfined",
        "--security-opt seccomp:unconfined",
    ]

    def _get_commands(self, config: dict[Any, Any], platform: str) -> list[str]:
        return pipeline_commands(config, platform)

    def check(self, config: dict[Any, Any], file_path: str, platform: str = "github") -> list[Finding]:
        findings: list[Finding] = []
        commands = self._get_commands(config, platform)

        for command in commands:
            for line_no, line in numbered_lines(command):
                line_stripped = line.strip()
                if "docker run" not in line_stripped and "docker exec" not in line_stripped:
                    continue
                for flag in self.PRIVILEGED_FLAGS:
                    if flag in line_stripped:
                        findings.append(Finding(
                            rule_id=self.rule_id,
                            title=self.title,
                            severity=self.severity,
                            description=f"Docker container is run with privileged flag '{flag}': '{line_stripped}'. This grants the container near-unrestricted access to the host kernel, devices, and other containers. A compromised pipeline step or malicious dependency running inside this container can escape to the runner host and pivot to other workloads.",
                            remediation=f"Remove '{flag}'. If a specific kernel capability is genuinely required, add only that capability with '--cap-add <SPECIFIC_CAP>'. For Docker-in-Docker scenarios, consider using rootless Docker (docker:dind-rootless) or Kaniko instead of running privileged containers.",
                            mitre_technique="T1611",
                            owasp_category="CICD-SEC-7",
                            file_path=file_path,
                            line_number=line_no,
                        ))
                        break
        return findings
