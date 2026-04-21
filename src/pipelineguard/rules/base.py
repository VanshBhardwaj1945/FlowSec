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



class BaseRule(ABC):
    rule_id: str
    title: str
    severity: Severity

    @abstractmethod
    def check(self, config: dict[str, Any], file_path: str) -> list[Finding]:
        ...