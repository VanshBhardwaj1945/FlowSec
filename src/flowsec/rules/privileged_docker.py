from typing import Any

from .base import BaseRule, Finding, Severity


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
                    commands.extend(s for s in scripts if isinstance(s, str))
        return commands

    def check(self, config: dict[Any, Any], file_path: str, platform: str = "github") -> list[Finding]:
        findings: list[Finding] = []
        commands = self._get_commands(config, platform)

        for command in commands:
            for line in command.split("\n"):
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
                        ))
                        break
        return findings
