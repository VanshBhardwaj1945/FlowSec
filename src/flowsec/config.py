import os
from fnmatch import fnmatch
from pathlib import Path

import yaml
from dotenv import load_dotenv

from .rules.base import Finding

USER_ENV_FILE = Path.home() / ".config" / "flowsec" / ".env"


def load_user_env(env_file: str | None = None) -> Path | None:
    """Load API tokens from a .env file the user chose, never from the scan target.

    FlowSec runs inside repositories it doesn't trust, so it must not pick up a
    .env from the working directory: a pull request could plant one that swaps
    tokens or API endpoints. Only these are read, first match wins:
    --env-file, $FLOWSEC_ENV_FILE, then ~/.config/flowsec/.env.
    Variables already set in the environment are never overridden.
    """
    chosen = env_file or os.getenv("FLOWSEC_ENV_FILE")
    path = Path(chosen).expanduser() if chosen else USER_ENV_FILE
    if not path.is_file():
        return None
    load_dotenv(path, override=False)
    return path


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
