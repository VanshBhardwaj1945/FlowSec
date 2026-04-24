from typing import Any
from .base import BaseRule, Finding, Severity

class MissingBranchProtectionRule(BaseRule):
    rule_id = "FS011"
    title = "Missing Branch Protection — Direct Push to Default Branch Possible"
    severity = Severity.HIGH

    def check(self, config: dict[str, Any], file_path: str) -> list[Finding]:
        # Branch protection is a repo setting not a workflow config
        # This rule is wired up via the GitHub API scanner
        # Scaffold here — full implementation in scanner refactor
        return []