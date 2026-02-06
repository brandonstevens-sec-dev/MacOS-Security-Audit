"""
Check: FileVault Full-Disk Encryption
=======================================
FileVault encrypts the entire startup volume using XTS-AES-128 with a
256-bit key. When enabled, data at rest is protected even if the physical
disk is removed from the machine.

Why it matters:
  - Protects data if the device is lost or stolen
  - Required by most compliance frameworks (CIS, NIST, SOC 2)
  - Apple Silicon Macs encrypt by default, but FileVault adds login-gated
    access control on top of hardware encryption

Commands used (read-only):
  - fdesetup status
"""

from lib.models import CheckResult, Severity, Status
from lib.util import run_cmd

REQUIRES_ADMIN = False


def check_filevault() -> CheckResult:
    """Check whether FileVault full-disk encryption is enabled."""
    stdout, err = run_cmd(["fdesetup", "status"])
    if err and stdout is None:
        return CheckResult(
            name="FileVault Encryption",
            status=Status.ERROR,
            severity=Severity.CRITICAL,
            description="Check if FileVault full-disk encryption is enabled.",
            detail=f"Could not determine FileVault status: {err}",
        )

    output = stdout or ""
    if "on" in output.lower() and "filevault is on" in output.lower():
        return CheckResult(
            name="FileVault Encryption",
            status=Status.PASS,
            severity=Severity.CRITICAL,
            description="Check if FileVault full-disk encryption is enabled.",
            detail="FileVault is ON — disk encryption is active.",
            raw_output=output,
        )

    if "off" in output.lower():
        return CheckResult(
            name="FileVault Encryption",
            status=Status.FAIL,
            severity=Severity.CRITICAL,
            description="Check if FileVault full-disk encryption is enabled.",
            detail="FileVault is OFF — disk is NOT encrypted.",
            recommendation="Enable FileVault: System Settings > Privacy & Security > FileVault > Turn On",
            raw_output=output,
        )

    # Encryption/decryption in progress
    return CheckResult(
        name="FileVault Encryption",
        status=Status.WARN,
        severity=Severity.CRITICAL,
        description="Check if FileVault full-disk encryption is enabled.",
        detail=f"FileVault status: {output}",
        raw_output=output,
    )


def run_checks() -> list[CheckResult]:
    return [check_filevault()]
