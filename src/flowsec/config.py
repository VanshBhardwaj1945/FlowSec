from fnmatch import fnmatch
from pathlib import Path

import yaml

from .rules.base import Finding


def load_ignore_config() -> list[dict[str, str]]:
    """Load ignore entries from .flowsec.yml in the current directory.

    Each entry has a rule_id and an optional file glob:

        ignore:
          - rule_id: FS006
          - rule_id: FS002
            file: "legacy/*.yml"
    """
    config_file = Path(".flowsec.yml")
    if not config_file.exists():
        return []

    with open(config_file) as f:
        config = yaml.safe_load(f)
    if not config:
        return []

    ignores = []
    for entry in config.get("ignore", []):
        if isinstance(entry, dict) and "rule_id" in entry:
            ignores.append(entry)
    return ignores


def is_ignored(finding: Finding, ignores: list[dict[str, str]]) -> bool:
    for entry in ignores:
        if finding.rule_id != entry["rule_id"]:
            continue
        file_glob = entry.get("file")
        if file_glob is None or fnmatch(finding.file_path, file_glob):
            return True
    return False


def apply_ignores(findings: list[Finding], ignores: list[dict[str, str]]) -> list[Finding]:
    return [f for f in findings if not is_ignored(f, ignores)]
