"""Core data model shared by every check, the reports and the AI layer."""

from __future__ import annotations

import hashlib
from dataclasses import asdict, dataclass, field
from enum import IntEnum


class Severity(IntEnum):
    """Ordered so severities can be compared: Severity.HIGH > Severity.LOW."""

    INFO = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

    @classmethod
    def parse(cls, value: str) -> Severity:
        return cls[value.strip().upper()]


@dataclass(frozen=True)
class Finding:
    """One misconfiguration on one resource.

    The ID is a hash of what was found and where, so the same problem keeps the same
    ID across scans. That lets you diff two reports and see what was fixed.
    """

    provider: str
    check_id: str
    title: str
    severity: Severity
    resource_type: str
    resource_id: str
    region: str
    remediation: str
    evidence: dict = field(default_factory=dict)
    references: tuple[str, ...] = ()

    @property
    def id(self) -> str:
        raw = f"{self.provider}|{self.check_id}|{self.region}|{self.resource_id}"
        return "F-" + hashlib.sha256(raw.encode()).hexdigest()[:10]

    def to_dict(self) -> dict:
        data = asdict(self)
        data["id"] = self.id
        data["severity"] = self.severity.name
        data["references"] = list(self.references)
        return data


def highest_severity(findings: list[Finding]) -> Severity:
    return max((f.severity for f in findings), default=Severity.INFO)
