"""
Check: File Sharing and Screen Sharing Services
=================================================
macOS includes built-in file sharing (SMB/AFP) and screen sharing (VNC-based)
services. These are convenient for local network use but expand the attack
surface when enabled unnecessarily.

Why it matters:
  - File Sharing exposes filesystem contents over the network
  - Screen Sharing allows remote GUI control of the machine
  - Both services listen on network ports and can be targeted
  - Should be disabled unless actively needed

Commands used (read-only):
  - launchctl list com.apple.smbd  (file sharing / SMB)
  - launchctl list com.apple.screensharing  (screen sharing)
"""

from lib.models import CheckResult, Severity, Status
from lib.util import run_cmd

REQUIRES_ADMIN = False


def _check_service(launchd_label: str, name: str, description: str,
                   recommendation: str) -> CheckResult:
    """Check whether a launchd service is loaded."""
    stdout, err = run_cmd(["launchctl", "list", launchd_label])

    # If the service is not loaded, launchctl returns an error
    if stdout is None or launchd_label not in (stdout + (err or "")):
        return CheckResult(
            name=name,
            status=Status.PASS,
            severity=Severity.MEDIUM,
            description=description,
            detail=f"{name} is not running.",
            raw_output=stdout or err,
        )

    return CheckResult(
        name=name,
        status=Status.WARN,
        severity=Severity.MEDIUM,
        description=description,
        detail=f"{name} is ENABLED and running.",
        recommendation=recommendation,
        raw_output=stdout,
    )


def check_file_sharing() -> CheckResult:
    return _check_service(
        launchd_label="com.apple.smbd",
        name="File Sharing (SMB)",
        description="Check if the SMB file sharing service is disabled.",
        recommendation="Disable if not needed: System Settings > General > Sharing > File Sharing",
    )


def check_screen_sharing() -> CheckResult:
    return _check_service(
        launchd_label="com.apple.screensharing",
        name="Screen Sharing",
        description="Check if Screen Sharing (VNC) is disabled.",
        recommendation="Disable if not needed: System Settings > General > Sharing > Screen Sharing",
    )


def run_checks() -> list[CheckResult]:
    return [check_file_sharing(), check_screen_sharing()]
