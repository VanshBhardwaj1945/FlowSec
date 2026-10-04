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


AZURE_SCRIPT_KEYS = ("script", "bash", "powershell", "pwsh")


def _azure_steps(config: dict[Any, Any]) -> list[dict[Any, Any]]:
    """Every step in an Azure pipeline: top-level steps, jobs, and stages of jobs."""
    steps: list[Any] = []
    jobs: list[Any] = []
    if isinstance(config.get("steps"), list):
        steps.extend(config["steps"])
    if isinstance(config.get("jobs"), list):
        jobs.extend(config["jobs"])
    for stage in config.get("stages") or []:
        if isinstance(stage, dict) and isinstance(stage.get("jobs"), list):
            jobs.extend(stage["jobs"])
    for job in jobs:
        if isinstance(job, dict) and isinstance(job.get("steps"), list):
            steps.extend(job["steps"])
    return [step for step in steps if isinstance(step, dict)]


def pipeline_commands(config: dict[Any, Any], platform: str) -> list[str]:
    """Every shell command a pipeline runs, as line-aware strings.

    GitHub: each step's ``run``. GitLab: each job's ``script``, ``before_script``
    and ``after_script``. Azure: ``script`` / ``bash`` / ``powershell`` / ``pwsh``
    steps under steps, jobs and stages (plus top-level job maps with ``script``).
    """
    commands: list[str] = []
    if platform == "github":
        jobs = config.get("jobs", {})
        if not isinstance(jobs, dict):
            return commands
        for job in jobs.values():
            if not isinstance(job, dict):
                continue
            for step in job.get("steps", []):
                if isinstance(step, dict) and isinstance(step.get("run"), str) and step["run"]:
                    commands.append(step["run"])
        return commands

    script_keys = ("script", "before_script", "after_script") if platform == "gitlab" else ("script",)
    for value in config.values():
        if not isinstance(value, dict):
            continue
        for key in script_keys:
            scripts = value.get(key, [])
            if isinstance(scripts, str):
                scripts = [scripts]
            if isinstance(scripts, list):
                commands.extend(s for s in scripts if isinstance(s, str))
    if platform == "azure":
        for step in _azure_steps(config):
            for key in AZURE_SCRIPT_KEYS:
                if isinstance(step.get(key), str):
                    commands.append(step[key])
    return commands
