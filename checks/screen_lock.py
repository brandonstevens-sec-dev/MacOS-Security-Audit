"""
Check: Screen Lock / Password Requirements
=============================================
macOS can require a password after the screen saver activates or the display
sleeps. The delay between sleep/screen saver and password prompt is
configurable. A short delay (ideally immediate) prevents unauthorized
physical access.

Why it matters:
  - Prevents unauthorized access when the user steps away
  - Required by CIS Benchmark (immediate password after sleep)
  - Unattended unlocked machines are a top physical security risk

Commands used (read-only):
  - sysadminctl -screenLock status  (macOS 10.13+)
  - defaults read com.apple.screensaver askForPassword
  - defaults read com.apple.screensaver askForPasswordDelay
"""

from lib.models import CheckResult, Severity, Status
from lib.util import read_plist_key, run_cmd


def check_screen_lock_enabled() -> CheckResult:
    """Check whether a password is required after sleep/screensaver."""
    # Try sysadminctl first (newer macOS)
    stdout, err = run_cmd(["sysadminctl", "-screenLock", "status"])
    output = stdout or err or ""

    if "screenlock is on" in output.lower():
        return CheckResult(
            name="Screen Lock Enabled",
            status=Status.PASS,
            severity=Severity.HIGH,
            description="Check if a password is required after sleep or screensaver.",
            detail="Screen lock is enabled.",
            raw_output=output,
        )

    if "screenlock is off" in output.lower():
        return CheckResult(
            name="Screen Lock Enabled",
            status=Status.FAIL,
            severity=Severity.HIGH,
            description="Check if a password is required after sleep or screensaver.",
            detail="Screen lock is OFF — no password required after sleep.",
            recommendation="Enable: System Settings > Lock Screen, or run: sysadminctl -screenLock on",
            raw_output=output,
        )

    # Fallback to screensaver plist
    val, plist_err = read_plist_key("com.apple.screensaver", "askForPassword")
    if val is not None:
        enabled = val.strip() == "1"
        return CheckResult(
            name="Screen Lock Enabled",
            status=Status.PASS if enabled else Status.FAIL,
            severity=Severity.HIGH,
            description="Check if a password is required after sleep or screensaver.",
            detail=f"askForPassword = {val.strip()} ({'enabled' if enabled else 'disabled'})",
            recommendation="" if enabled else "Enable: System Settings > Lock Screen",
            raw_output=val,
        )

    return CheckResult(
        name="Screen Lock Enabled",
        status=Status.WARN,
        severity=Severity.HIGH,
        description="Check if a password is required after sleep or screensaver.",
        detail="Could not determine screen lock status. This check may require running as the logged-in user.",
    )


def check_screen_lock_delay() -> CheckResult:
    """Check the delay before password is required after sleep/screensaver."""
    val, err = read_plist_key("com.apple.screensaver", "askForPasswordDelay")
    if val is None:
        return CheckResult(
            name="Screen Lock Delay",
            status=Status.WARN,
            severity=Severity.MEDIUM,
            description="Check the delay before password is required.",
            detail="Could not read askForPasswordDelay. This check may require running as the logged-in user.",
        )

    try:
        delay = int(val.strip())
    except ValueError:
        return CheckResult(
            name="Screen Lock Delay",
            status=Status.WARN,
            severity=Severity.MEDIUM,
            description="Check the delay before password is required.",
            detail=f"Unexpected value: {val}",
            raw_output=val,
        )

    if delay == 0:
        status = Status.PASS
        detail = "Password required immediately (0 seconds)."
    elif delay <= 5:
        status = Status.PASS
        detail = f"Password required after {delay} second(s)."
    elif delay <= 60:
        status = Status.WARN
        detail = f"Password required after {delay} second(s) — consider reducing."
    else:
        status = Status.FAIL
        detail = f"Password required after {delay} second(s) — too long."

    return CheckResult(
        name="Screen Lock Delay",
        status=status,
        severity=Severity.MEDIUM,
        description="Check the delay before password is required.",
        detail=detail,
        recommendation="Set to immediate: System Settings > Lock Screen > Require password after screen saver begins or display is turned off > Immediately",
        raw_output=val,
    )


def run_checks() -> list[CheckResult]:
    return [check_screen_lock_enabled(), check_screen_lock_delay()]
