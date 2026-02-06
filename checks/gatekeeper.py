"""
Check: Gatekeeper
==================
Gatekeeper verifies that applications are signed by an identified developer
and/or distributed through the Mac App Store before allowing them to run.
It is macOS's primary defense against malware delivered via downloaded apps.

Why it matters:
  - Prevents execution of unsigned or tampered applications
  - First line of defense against trojanized software
  - Required by CIS macOS Benchmark (ensure "assessments enabled")

Commands used (read-only):
  - spctl --status
"""

from lib.models import CheckResult, Severity, Status
from lib.util import run_cmd

REQUIRES_ADMIN = False


def check_gatekeeper() -> CheckResult:
    """Check whether Gatekeeper is enabled."""
    stdout, err = run_cmd(["spctl", "--status"])

    # spctl may print to stderr even on success; check both streams
    output = stdout or err or ""
    if "assessments enabled" in output.lower():
        return CheckResult(
            name="Gatekeeper",
            status=Status.PASS,
            severity=Severity.CRITICAL,
            description="Verify Gatekeeper is enforcing app code-signing checks.",
            detail="Gatekeeper is enabled (assessments enabled).",
            raw_output=output,
        )

    if "assessments disabled" in output.lower():
        return CheckResult(
            name="Gatekeeper",
            status=Status.FAIL,
            severity=Severity.CRITICAL,
            description="Verify Gatekeeper is enforcing app code-signing checks.",
            detail="Gatekeeper is DISABLED — unsigned apps can execute freely.",
            recommendation="Enable Gatekeeper: sudo spctl --master-enable",
            raw_output=output,
        )

    return CheckResult(
        name="Gatekeeper",
        status=Status.ERROR,
        severity=Severity.CRITICAL,
        description="Verify Gatekeeper is enforcing app code-signing checks.",
        detail=f"Could not determine Gatekeeper status: {output}",
        raw_output=output,
    )


def run_checks() -> list[CheckResult]:
    return [check_gatekeeper()]
