from typing import Any

from .base import BaseRule, Finding, Severity


class DockerInDockerRule(BaseRule):
    rule_id = "FS038"
    title = "Docker-in-Docker Service — Privileged Runner Required"
    severity = Severity.HIGH

    def _service_images(self, value: Any) -> list[str]:
        images: list[str] = []
        services = value.get("services") if isinstance(value, dict) else None
        if isinstance(services, str):
            images.append(services)
        elif isinstance(services, list):
            for service in services:
                if isinstance(service, str):
                    images.append(service)
                elif isinstance(service, dict) and isinstance(service.get("name"), str):
                    images.append(service["name"])
        return images

    def check(self, config: dict[Any, Any], file_path: str, platform: str = "github") -> list[Finding]:
        if platform != "gitlab":
            return []
        findings: list[Finding] = []
        candidates = [config] + [v for v in config.values() if isinstance(v, dict)]
        for value in candidates:
            for image in self._service_images(value):
                if "docker" in image and "dind" in image:
                    findings.append(Finding(
                        rule_id=self.rule_id,
                        title=self.title,
                        severity=self.severity,
                        description=f"A Docker-in-Docker service is configured: '{image}'. dind requires the GitLab runner to run in privileged mode, which gives any job full access to the host kernel — a job can escape the container and take over the runner.",
                        remediation="Avoid dind where possible. Use a rootless image builder such as Kaniko or buildah, or a dedicated build service, so the runner does not need privileged mode.",
                        mitre_technique="T1611",
                        owasp_category="CICD-SEC-7",
                        file_path=file_path,
                    ))
        return findings
