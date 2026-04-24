from typing import Any
from .base import BaseRule, Finding, Severity


class ArtifactSigningRule(BaseRule):
    rule_id = "FS008"
    title = "Missing Artifact Signing — No Tamper Protection"
    severity = Severity.MEDIUM

    # Actions that publish artifacts or packages without signing
    PUBLISHING_ACTIONS = [
        "actions/upload-artifact",
        "pypa/gh-action-pypi-publish",
        "docker/build-push-action",
        "softprops/action-gh-release",
    ]

    # Actions that indicate signing is present
    SIGNING_ACTIONS = [
        "sigstore/cosign-installer",
        "anchore/sbom-action",
        "slsa-framework/slsa-github-generator",
    ]

    def _extract_uses(self, config: dict[str, Any]) -> list[str]:
        uses = []
        jobs = config.get("jobs", {})
        for job in jobs.values():
            for step in job.get("steps", []):
                if "uses" in step:
                    uses.append(step["uses"])
        return uses

    def check(self, config: dict[str, Any], file_path: str) -> list[Finding]:
        findings = []
        uses = self._extract_uses(config)

        publishes_artifact = any(
            any(action in step for action in self.PUBLISHING_ACTIONS)
            for step in uses
        )

        has_signing = any(
            any(action in step for action in self.SIGNING_ACTIONS)
            for step in uses
        )

        if publishes_artifact and not has_signing:
            findings.append(Finding(
                rule_id=self.rule_id,
                title=self.title,
                severity=self.severity,
                description="This pipeline publishes artifacts or packages without cryptographic signing. Without signed artifacts, consumers have no way to verify that what they downloaded was actually built by your pipeline and has not been tampered with in transit or storage.",
                remediation="Add artifact signing using Sigstore/cosign or the SLSA framework. For Docker images use cosign to sign after push. For PyPI packages use sigstore. For GitHub releases attach SLSA provenance using slsa-framework/slsa-github-generator.",
                mitre_technique="T1553",
                file_path=file_path,
                owasp_category="CICD-SEC-8",

            ))

        return findings