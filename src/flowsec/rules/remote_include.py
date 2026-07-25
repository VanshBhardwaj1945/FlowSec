from typing import Any

from .base import BaseRule, Finding, Severity


class RemoteIncludeRule(BaseRule):
    rule_id = "FS032"
    title = "Unpinned Remote Include — External Pipeline Config Pulled at Runtime"
    severity = Severity.HIGH

    def _is_sha(self, ref: str) -> bool:
        return len(ref) == 40 and all(c in "0123456789abcdef" for c in ref.lower())

    def _check_gitlab(self, config: dict[Any, Any], file_path: str) -> list[Finding]:
        findings: list[Finding] = []
        includes = config.get("include")
        if includes is None:
            return findings
        if isinstance(includes, (str, dict)):
            includes = [includes]
        if not isinstance(includes, list):
            return findings

        for entry in includes:
            if isinstance(entry, str) and entry.startswith(("http://", "https://")):
                findings.append(self._finding(f"include: remote '{entry}'", file_path))
            elif isinstance(entry, dict):
                if "remote" in entry:
                    findings.append(self._finding(f"include: remote '{entry.get('remote')}'", file_path))
                elif "project" in entry:
                    ref = str(entry.get("ref", ""))
                    if not self._is_sha(ref):
                        findings.append(self._finding(f"include: project '{entry.get('project')}' at ref '{ref or 'default branch'}'", file_path))
        return findings

    def _check_azure(self, config: dict[Any, Any], file_path: str) -> list[Finding]:
        findings: list[Finding] = []
        resources = config.get("resources", {})
        if not isinstance(resources, dict):
            return findings
        repositories = resources.get("repositories", [])
        if not isinstance(repositories, list):
            return findings
        for repo in repositories:
            if not isinstance(repo, dict):
                continue
            ref = str(repo.get("ref", ""))
            # Azure refs look like refs/tags/v1 or refs/heads/main — mutable unless a full SHA
            if not self._is_sha(ref.replace("refs/tags/", "").replace("refs/heads/", "")):
                name = repo.get("repository") or repo.get("name") or "external repo"
                findings.append(self._finding(f"repository resource '{name}' at ref '{ref or 'default branch'}'", file_path))
        return findings

    def _finding(self, detail: str, file_path: str) -> Finding:
        return Finding(
            rule_id=self.rule_id,
            title=self.title,
            severity=self.severity,
            description=f"Pipeline configuration is pulled from an external source that is not pinned to a commit SHA: {detail}. Whoever controls that source can change what your pipeline runs at any time — the same supply-chain risk as an unpinned action.",
            remediation="Pin external includes and repository resources to a full commit SHA rather than a branch, tag, or bare URL. For GitLab, prefer 'include: project' with a SHA 'ref'; for Azure, set the repository resource 'ref' to a commit SHA.",
            mitre_technique="T1195.001",
            owasp_category="CICD-SEC-3",
            file_path=file_path,
        )

    def check(self, config: dict[Any, Any], file_path: str, platform: str = "github") -> list[Finding]:
        if platform == "gitlab":
            return self._check_gitlab(config, file_path)
        if platform == "azure":
            return self._check_azure(config, file_path)
        return []
