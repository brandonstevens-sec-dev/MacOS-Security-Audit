"""
Check: macOS Application Firewall (ALF)
========================================
The macOS Application Firewall controls incoming connections on a per-app basis.
When enabled, it blocks unauthorized incoming connections and can optionally
enable stealth mode (which prevents the machine from responding to probing
requests such as ICMP ping).

Why it matters:
  - Blocks unsolicited inbound network connections
  - Stealth mode reduces attack surface by hiding the machine on the network
  - Required by CIS macOS Benchmark and most compliance frameworks

Commands used (read-only):
  - /usr/libexec/ApplicationFirewall/socketfilterfw --getglobalstate
  - /usr/libexec/ApplicationFirewall/socketfilterfw --getstealthmode
"""

from lib.models import CheckResult, Severity, Status
from lib.util import run_cmd

_FW_CMD = "/usr/libexec/ApplicationFirewall/socketfilterfw"


def check_firewall_enabled() -> CheckResult:
    """Check whether the macOS Application Firewall is enabled."""
    stdout, err = run_cmd([_FW_CMD, "--getglobalstate"])
    if err and stdout is None:
        return CheckResult(
            name="Firewall Enabled",
            status=Status.ERROR,
            severity=Severity.HIGH,
            description="Check if the macOS Application Firewall is enabled.",
            detail=f"Could not determine firewall state: {err}",
        )

    enabled = stdout is not None and "enabled" in stdout.lower()
    return CheckResult(
        name="Firewall Enabled",
        status=Status.PASS if enabled else Status.FAIL,
        severity=Severity.HIGH,
        description="Check if the macOS Application Firewall is enabled.",
        detail=stdout or "Unknown",
        recommendation="Enable the firewall: System Settings > Network > Firewall, or run: sudo /usr/libexec/ApplicationFirewall/socketfilterfw --setglobalstate on",
        raw_output=stdout,
    )


def check_stealth_mode() -> CheckResult:
    """Check whether firewall stealth mode is enabled."""
    stdout, err = run_cmd([_FW_CMD, "--getstealthmode"])
    if err and stdout is None:
        return CheckResult(
            name="Firewall Stealth Mode",
            status=Status.ERROR,
            severity=Severity.MEDIUM,
            description="Check if firewall stealth mode is enabled.",
            detail=f"Could not determine stealth mode: {err}",
        )

    enabled = stdout is not None and "enabled" in stdout.lower()
    return CheckResult(
        name="Firewall Stealth Mode",
        status=Status.PASS if enabled else Status.WARN,
        severity=Severity.MEDIUM,
        description="Check if firewall stealth mode is enabled.",
        detail=stdout or "Unknown",
        recommendation="Enable stealth mode: sudo /usr/libexec/ApplicationFirewall/socketfilterfw --setstealthmode on",
        raw_output=stdout,
    )


def run_checks() -> list[CheckResult]:
    return [check_firewall_enabled(), check_stealth_mode()]
