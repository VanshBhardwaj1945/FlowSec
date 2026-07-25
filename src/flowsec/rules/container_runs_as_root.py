from typing import Any

from .base import BaseRule, Finding, Severity


class ContainerRunsAsRootRule(BaseRule):
    rule_id = "FS020"
    title = "Container Running as Root — Elevated Privilege in Pipeline"
    severity = Severity.HIGH

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
        commands = self._get_commands(config, platform)

        for command in commands:
            for line in command.split("\n"):
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
                        ))
                        break
        return findings