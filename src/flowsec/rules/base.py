import re
from abc import ABC, abstractmethod
from dataclasses import dataclass
from enum import Enum
from typing import Any


class Severity(Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


@dataclass
class Finding:
    rule_id: str
    title: str
    severity: Severity
    description: str
    remediation: str
    mitre_technique: str
    file_path: str
    line_number: int = 0
    narrative: str = ""
    owasp_category: str = ""




class BaseRule(ABC):
    rule_id: str
    title: str
    severity: Severity

    @abstractmethod
    def check(self, config: dict[Any, Any], file_path: str, platform: str = "github") -> list[Finding]:
        ...

def line_of(node: Any, key: Any = None) -> int:
    """1-based line of a parsed YAML node, or of ``key`` inside a mapping.

    Works on the LineStr / LineDict / LineList values the parser produces and
    returns 0 for anything else (a plain dict built in a test, a bool, ...).
    """
    if key is not None:
        key_lines = getattr(node, "key_lines", None)
        if key_lines and key in key_lines:
            return int(key_lines[key])
    return int(getattr(node, "line", 0))


def numbered_lines(text: str) -> list[tuple[int, str]]:
    """Split a (possibly multi-line) YAML string into (file line, text) pairs."""
    base = getattr(text, "line", 0)
    block = getattr(text, "block", False)
    return [
        (base + index if base and block else base, line)
        for index, line in enumerate(text.split("\n"))
    ]


_EXPRESSION = re.compile(r"\$\{\{(.*?)\}\}")
_CONTEXT_PATH = re.compile(r"\bgithub(?:\.[A-Za-z_][\w-]*)*")


def untrusted_context(text: str, dangerous: list[str] | tuple[str, ...]) -> str | None:
    """Return the first attacker-controlled github.* path used in a ${{ }} expression.

    Spacing inside the braces doesn't matter (``${{github.head_ref}}`` counts),
    and a path that contains a dangerous one is caught too: ``toJSON(github.event)``
    hands over every field of the event, titles and bodies included.
    """
    for expression in _EXPRESSION.findall(text):
        for path in _CONTEXT_PATH.findall(expression):
            for ctx in dangerous:
                if path == ctx or ctx.startswith(path + ".") or path.startswith(ctx + "."):
                    return str(path)
    return None
