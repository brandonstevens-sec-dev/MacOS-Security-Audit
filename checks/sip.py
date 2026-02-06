"""
Check: System Integrity Protection (SIP)
==========================================
SIP restricts the root account and limits actions that root can perform on
protected parts of macOS. It prevents modification of system files, kernel
extensions loading from untrusted sources, and other low-level operations.

Why it matters:
  - Prevents rootkits and kernel-level malware
  - Protects critical system binaries from tampering
  - Disabling SIP (common for dev work) leaves the system exposed
  - Can only be disabled from Recovery Mode, so presence of "disabled"
    indicates deliberate action

Commands used (read-only):
  - csrutil status
"""

from lib.models import CheckResult, Severity, Status
from lib.util import run_cmd


def check_sip() -> CheckResult:
    """Check whether System Integrity Protection is enabled."""
    stdout, err = run_cmd(["csrutil", "status"])
    output = stdout or err or ""

    if "enabled" in output.lower():
        return CheckResult(
            name="System Integrity Protection (SIP)",
            status=Status.PASS,
            severity=Severity.CRITICAL,
            description="Verify SIP is enabled to protect system files.",
            detail="SIP is enabled.",
            raw_output=output,
        )

    if "disabled" in output.lower():
        return CheckResult(
            name="System Integrity Protection (SIP)",
            status=Status.FAIL,
            severity=Severity.CRITICAL,
            description="Verify SIP is enabled to protect system files.",
            detail="SIP is DISABLED — system files are unprotected.",
            recommendation="Re-enable SIP: boot into Recovery Mode (Cmd+R) and run: csrutil enable",
            raw_output=output,
        )

    return CheckResult(
        name="System Integrity Protection (SIP)",
        status=Status.ERROR,
        severity=Severity.CRITICAL,
        description="Verify SIP is enabled to protect system files.",
        detail=f"Could not determine SIP status: {output}",
        raw_output=output,
    )


def run_checks() -> list[CheckResult]:
    return [check_sip()]
