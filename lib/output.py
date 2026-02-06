"""Terminal output formatting with ANSI colors."""

import json
import sys
from datetime import datetime, timezone

from lib.models import AuditReport, CheckResult, Status

# ANSI color codes
_COLORS = {
    Status.PASS: "\033[92m",    # green
    Status.FAIL: "\033[91m",    # red
    Status.WARN: "\033[93m",    # yellow
    Status.SKIPPED: "\033[96m", # cyan
    Status.ERROR: "\033[90m",   # gray
}
_BOLD = "\033[1m"
_RESET = "\033[0m"


def _color(status: Status, text: str) -> str:
    return f"{_COLORS[status]}{text}{_RESET}"


def _status_icon(status: Status) -> str:
    icons = {
        Status.PASS: _color(status, "[PASS]"),
        Status.FAIL: _color(status, "[FAIL]"),
        Status.WARN: _color(status, "[WARN]"),
        Status.SKIPPED: _color(status, "[SKIP]"),
        Status.ERROR: _color(status, "[ERR ]"),
    }
    return icons[status]


def print_banner() -> None:
    banner = rf"""
{_BOLD}┌─────────────────────────────────────────────────┐
│           macOS Security Audit Tool              │
│                   v0.2.0                         │
│                                                  │
│  Read-only audit — no system changes are made.   │
└─────────────────────────────────────────────────┘{_RESET}
"""
    print(banner)


def print_privilege_notice(is_admin: bool) -> None:
    """Print a notice about the current privilege level."""
    if is_admin:
        print(f"  {_COLORS[Status.PASS]}Running with admin privileges — full audit.{_RESET}")
    else:
        print(f"  {_COLORS[Status.WARN]}Running without admin privileges — some checks will be skipped.{_RESET}")
        print(f"  {_COLORS[Status.WARN]}Re-run with sudo for a complete audit: sudo python3 macos_audit.py{_RESET}")
    print()


def print_system_info(info: dict) -> None:
    print(f"{_BOLD}System Information{_RESET}")
    print("─" * 50)
    for key, value in info.items():
        print(f"  {key:<20} {value}")
    print()


def print_result(result: CheckResult) -> None:
    icon = _status_icon(result.status)
    print(f"  {icon}  {result.name}")
    print(f"         {result.detail}")
    if result.status == Status.FAIL and result.recommendation:
        print(f"         {_COLORS[Status.WARN]}→ {result.recommendation}{_RESET}")
    print()


def print_summary(report: AuditReport) -> None:
    pct = report.compliance_pct
    if pct >= 80:
        pct_color = _COLORS[Status.PASS]
    elif pct >= 50:
        pct_color = _COLORS[Status.WARN]
    else:
        pct_color = _COLORS[Status.FAIL]

    print("─" * 50)
    print(f"{_BOLD}Audit Summary{_RESET}")
    print("─" * 50)
    print(f"  Total checks:   {report.total}")
    print(f"  {_COLORS[Status.PASS]}Passed:        {report.passed}{_RESET}")
    print(f"  {_COLORS[Status.FAIL]}Failed:        {report.failed}{_RESET}")
    print(f"  {_COLORS[Status.WARN]}Warnings:      {report.warnings}{_RESET}")
    if report.skipped:
        print(f"  {_COLORS[Status.SKIPPED]}Skipped:       {report.skipped}  (requires admin){_RESET}")
    if report.errors:
        print(f"  {_COLORS[Status.ERROR]}Errors:        {report.errors}{_RESET}")
    print(f"  Compliance:     {pct_color}{pct}%{_RESET}")

    if report.skipped:
        print(f"\n  {_COLORS[Status.SKIPPED]}* {report.skipped} check(s) skipped — "
              f"run with sudo for complete results{_RESET}")

    print("─" * 50)
    print()


def write_json_report(report: AuditReport, path: str) -> None:
    data = report.to_dict()
    data["generated_at"] = datetime.now(timezone.utc).isoformat()
    with open(path, "w") as f:
        json.dump(data, f, indent=2)
    print(f"JSON report written to: {path}")
