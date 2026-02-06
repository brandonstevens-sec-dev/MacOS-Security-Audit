"""Data models for audit check results."""

import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional

_ANSI_RE = re.compile(r"\033\[[0-9;]*m")


class Status(Enum):
    """Result status for a security check."""
    PASS = "PASS"
    FAIL = "FAIL"
    WARN = "WARNING"
    INFO = "INFO"
    SKIPPED = "SKIPPED"
    ERROR = "ERROR"


class Severity(Enum):
    """Severity level if a check fails."""
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


@dataclass
class CheckResult:
    """Result from a single security audit check."""
    name: str
    status: Status
    severity: Severity
    description: str
    detail: str
    recommendation: str = ""
    raw_output: Optional[str] = None

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "status": self.status.value,
            "severity": self.severity.value,
            "description": self.description,
            "detail": _ANSI_RE.sub("", self.detail),
            "recommendation": self.recommendation,
        }


@dataclass
class AuditReport:
    """Complete audit report containing all check results."""
    results: list[CheckResult] = field(default_factory=list)
    system_info: dict = field(default_factory=dict)

    @property
    def total(self) -> int:
        return len(self.results)

    @property
    def passed(self) -> int:
        return sum(1 for r in self.results if r.status == Status.PASS)

    @property
    def failed(self) -> int:
        return sum(1 for r in self.results if r.status == Status.FAIL)

    @property
    def warnings(self) -> int:
        return sum(1 for r in self.results if r.status == Status.WARN)

    @property
    def errors(self) -> int:
        return sum(1 for r in self.results if r.status == Status.ERROR)

    @property
    def skipped(self) -> int:
        return sum(1 for r in self.results if r.status == Status.SKIPPED)

    @property
    def compliance_pct(self) -> float:
        scorable = [
            r for r in self.results
            if r.status not in (Status.ERROR, Status.SKIPPED, Status.INFO)
        ]
        if not scorable:
            return 0.0
        passed = sum(1 for r in scorable if r.status == Status.PASS)
        return round((passed / len(scorable)) * 100, 1)

    def to_dict(self) -> dict:
        return {
            "system_info": self.system_info,
            "summary": {
                "total_checks": self.total,
                "passed": self.passed,
                "failed": self.failed,
                "warnings": self.warnings,
                "errors": self.errors,
                "skipped": self.skipped,
                "compliance_percentage": self.compliance_pct,
            },
            "results": [r.to_dict() for r in self.results],
        }
