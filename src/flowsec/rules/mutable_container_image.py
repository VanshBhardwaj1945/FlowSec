from typing import Any

from .base import BaseRule, Finding, Severity


class MutableContainerImageRule(BaseRule):
    rule_id = "FS014"
    title = "Mutable Container Image — Unpinned Image Tag in Pipeline"
    severity = Severity.MEDIUM

    def _is_mutable(self, image: str) -> bool:
        if not isinstance(image, str) or not image.strip():
            return False
        image = image.strip()
        # Pinned by SHA digest — always safe
        if "@sha256:" in image:
            return False
        # Explicit :latest tag
        if image.endswith(":latest"):
            return True
        # No tag on the final path segment means implicit :latest
        last_segment = image.split("/")[-1]
        if ":" not in last_segment:
            return True
        return False

    def _make_finding(self, image: str, file_path: str) -> Finding:
        base = image.split(":")[0].split("@")[0]
        return Finding(
            rule_id=self.rule_id,
            title=self.title,
            severity=self.severity,
            description=f"Container image '{image}' uses a mutable tag. Mutable tags can silently point to a different image after a push to the registry, allowing a compromised or hijacked image to inject malicious code into your pipeline without any change to your workflow file.",
            remediation=f"Pin the image to an immutable SHA digest: '{base}@sha256:<digest>'. Obtain the digest with 'docker inspect --format={{{{.RepoDigests}}}} {image}' or from your registry's image details page.",
            mitre_technique="T1195.001",
            owasp_category="CICD-SEC-3",
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
                # Job-level container
                container = job.get("container")
                if isinstance(container, str) and self._is_mutable(container):
                    findings.append(self._make_finding(container, file_path))
                elif isinstance(container, dict):
                    img = container.get("image", "")
                    if self._is_mutable(img):
                        findings.append(self._make_finding(img, file_path))
                # Job-level services
                for svc in job.get("services", {}).values():
                    if isinstance(svc, str) and self._is_mutable(svc):
                        findings.append(self._make_finding(svc, file_path))
                    elif isinstance(svc, dict):
                        img = svc.get("image", "")
                        if self._is_mutable(img):
                            findings.append(self._make_finding(img, file_path))
                # Steps using docker:// action syntax
                for step in job.get("steps", []):
                    if not isinstance(step, dict):
                        continue
                    uses = step.get("uses", "")
                    if uses.startswith("docker://"):
                        img = uses[len("docker://"):]
                        if self._is_mutable(img):
                            findings.append(self._make_finding(uses, file_path))

        elif platform in ("gitlab", "azure"):
            # Global image
            global_image = config.get("image")
            if isinstance(global_image, str) and self._is_mutable(global_image):
                findings.append(self._make_finding(global_image, file_path))
            elif isinstance(global_image, dict):
                img = global_image.get("name", "")
                if self._is_mutable(img):
                    findings.append(self._make_finding(img, file_path))
            # Per-job image
            for key, value in config.items():
                if key.startswith("__line_") or not isinstance(value, dict):
                    continue
                job_image = value.get("image")
                if isinstance(job_image, str) and self._is_mutable(job_image):
                    findings.append(self._make_finding(job_image, file_path))
                elif isinstance(job_image, dict):
                    img = job_image.get("name", "")
                    if self._is_mutable(img):
                        findings.append(self._make_finding(img, file_path))

        return findings
