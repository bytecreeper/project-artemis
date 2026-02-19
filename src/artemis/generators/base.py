"""Base generator interface and common types."""

from __future__ import annotations

import abc
import enum
from dataclasses import dataclass, field
from typing import Any


class RuleFormat(str, enum.Enum):
    SIGMA = "sigma"
    YARA = "yara"
    SPLUNK = "splunk"
    KQL = "kql"
    SNORT = "snort"


class Severity(str, enum.Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class ThreatDescription:
    """Natural language threat description — input to generators."""

    description: str
    severity: Severity = Severity.MEDIUM
    mitre_techniques: list[str] = field(default_factory=list)
    mitre_tactics: list[str] = field(default_factory=list)
    tags: list[str] = field(default_factory=list)
    context: dict[str, Any] = field(default_factory=dict)


@dataclass
class GeneratedRule:
    """Output of a generator — the detection rule plus metadata."""

    format: RuleFormat
    content: str
    name: str = ""
    description: str = ""
    severity: Severity = Severity.MEDIUM
    mitre_techniques: list[str] = field(default_factory=list)
    confidence: float = 0.0  # 0-1, how confident the AI is
    raw_response: str = ""  # full AI response for debugging


class RuleGenerator(abc.ABC):
    """Base class for detection rule generators."""

    format: RuleFormat

    @abc.abstractmethod
    async def generate(self, threat: ThreatDescription) -> GeneratedRule:
        """Generate a detection rule from a threat description."""

    @abc.abstractmethod
    async def validate(self, rule: str) -> tuple[bool, list[str]]:
        """Validate rule syntax. Returns (is_valid, errors)."""
