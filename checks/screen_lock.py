"""
Check: Screen Lock / Password Requirements
=============================================
macOS can require a password after the display sleeps or the screen saver
activates. The delay between sleep/screen saver and password prompt is
configurable. A short delay (ideally immediate) prevents unauthorized
physical access.

Why it matters:
  - Prevents unauthorized access when the user steps away
  - Required by CIS Benchmark (immediate password after sleep)
  - Unattended unlocked machines are a top physical security risk

Detection strategy (in priority order):
  1. sysadminctl -screenLock status — outputs to STDERR, not stdout.
     Possible responses (after the timestamp prefix):
       "screenLock is off"        → disabled
       "screenLock is immediate"  → enabled, 0 sec delay
       "screenLock is <N>"        → enabled, N second delay
  2. MDM managed preferences:
     /Library/Managed Preferences/com.apple.screensaver askForPassword
  3. Configuration profiles:
     system_profiler SPConfigurationProfileDataType (grep for askForPassword)

Legacy note:
  - defaults read com.apple.screensaver askForPassword has returned empty
    since macOS 10.13 (2017). Apple moved the setting to an encrypted
    keychain (~/Library/Keychains/<UUID>/User.kb). Do NOT rely on it.
"""

import logging
import re
from typing import Optional

from lib.models import CheckResult, Severity, Status
from lib.util import read_plist_key_full, run_cmd

log = logging.getLogger(__name__)

REQUIRES_ADMIN = False


def _parse_sysadminctl_output(stdout: str, stderr: str) -> Optional[dict]:
    """Parse sysadminctl -screenLock status output.

    sysadminctl writes its output to STDERR in the format:
        2025-01-15 10:30:45.123 sysadminctl[1234:5678] screenLock is <value>

    Returns dict with:
        {"enabled": bool, "delay": int_or_None, "raw": str}
    or None if the output could not be parsed.
    """
    # sysadminctl writes to stderr; combine both streams
    output = (stderr or "") + " " + (stdout or "")
    output_lower = output.lower()
    log.debug("  sysadminctl raw output: stdout=%r stderr=%r", stdout, stderr)

    if "screenlock is off" in output_lower:
        return {"enabled": False, "delay": None, "raw": output.strip()}

    if "screenlock is immediate" in output_lower:
        return {"enabled": True, "delay": 0, "raw": output.strip()}

    # Match "screenLock is <number>" (seconds)
    m = re.search(r"screenlock is (\d+)", output_lower)
    if m:
        delay = int(m.group(1))
        return {"enabled": True, "delay": delay, "raw": output.strip()}

    return None


def _check_mdm_profile() -> Optional[dict]:
    """Check MDM managed preferences and config profiles for screen lock.

    Returns dict with:
        {"enabled": bool, "delay": int_or_None, "source": str}
    or None if no profile-based setting found.
    """
    # Check managed preferences plist
    managed = read_plist_key_full(
        "/Library/Managed Preferences/com.apple.screensaver", "askForPassword"
    )
    if managed.exists and managed.as_bool is not None:
        delay_pv = read_plist_key_full(
            "/Library/Managed Preferences/com.apple.screensaver", "askForPasswordDelay"
        )
        try:
            delay = int(delay_pv.value) if delay_pv.exists and delay_pv.value else None
        except (ValueError, TypeError):
            delay = None

        log.debug("  MDM managed prefs: askForPassword=%r, delay=%r",
                  managed.value, delay)
        return {
            "enabled": managed.as_bool,
            "delay": delay,
            "source": f"MDM managed prefs (askForPassword={managed.value!r})",
        }

    # Check configuration profiles via system_profiler
    stdout, err = run_cmd(
        ["system_profiler", "SPConfigurationProfileDataType"], timeout=15,
    )
    if stdout and "askForPassword = 1" in stdout:
        log.debug("  Config profile found with askForPassword = 1")
        # Try to extract delay from profile output too
        delay = None
        m = re.search(r"askForPasswordDelay\s*=\s*(\d+)", stdout)
        if m:
            delay = int(m.group(1))
        return {
            "enabled": True,
            "delay": delay,
            "source": "Configuration profile (askForPassword = 1)",
        }

    return None


def check_screen_lock() -> CheckResult:
    """Consolidated check for screen lock status and delay.

    Tries multiple detection methods and reports the result from the
    most reliable source available.
    """
    sources_tried = []

    # --- Method 1: sysadminctl (most reliable on unmanaged machines) ---
    stdout, stderr = run_cmd(["sysadminctl", "-screenLock", "status"])
    sysadmin = _parse_sysadminctl_output(stdout, stderr)

    if sysadmin is not None:
        sources_tried.append(f"sysadminctl: {sysadmin['raw']}")
        log.debug("  sysadminctl parsed: enabled=%s delay=%s",
                  sysadmin["enabled"], sysadmin["delay"])

        if not sysadmin["enabled"]:
            return CheckResult(
                name="Screen Lock",
                status=Status.FAIL,
                severity=Severity.HIGH,
                description="Check if a password is required after sleep or screensaver.",
                detail=f"Screen lock is OFF — no password required.\n"
                       f"  Source: sysadminctl",
                recommendation="Enable: System Settings > Lock Screen > Require password... > Immediately",
                raw_output=" | ".join(sources_tried),
            )

        # Enabled — check the delay
        delay = sysadmin["delay"]
        if delay is not None and delay == 0:
            delay_detail = "immediately"
            status = Status.PASS
        elif delay is not None and delay <= 5:
            delay_detail = f"after {delay} second(s)"
            status = Status.PASS
        elif delay is not None and delay <= 60:
            delay_detail = f"after {delay} second(s) — consider reducing"
            status = Status.WARN
        elif delay is not None:
            delay_detail = f"after {delay} second(s) — too long"
            status = Status.FAIL
        else:
            delay_detail = "(delay unknown)"
            status = Status.PASS

        return CheckResult(
            name="Screen Lock",
            status=status,
            severity=Severity.HIGH,
            description="Check if a password is required after sleep or screensaver.",
            detail=f"Screen lock is enabled — password required {delay_detail}.\n"
                   f"  Source: sysadminctl",
            recommendation="" if status == Status.PASS else
                "Set to immediate: System Settings > Lock Screen > Require password... > Immediately",
            raw_output=" | ".join(sources_tried),
        )

    sources_tried.append("sysadminctl: could not parse output")
    log.debug("  sysadminctl: no parseable output, trying MDM/profile")

    # --- Method 2: MDM managed preferences / config profiles ---
    mdm = _check_mdm_profile()
    if mdm is not None:
        sources_tried.append(f"profile: {mdm['source']}")

        if not mdm["enabled"]:
            return CheckResult(
                name="Screen Lock",
                status=Status.FAIL,
                severity=Severity.HIGH,
                description="Check if a password is required after sleep or screensaver.",
                detail=f"Screen lock is disabled by profile.\n"
                       f"  Source: {mdm['source']}",
                recommendation="Enable: System Settings > Lock Screen > Require password... > Immediately",
                raw_output=" | ".join(sources_tried),
            )

        delay = mdm["delay"]
        if delay is not None and delay <= 5:
            delay_detail = f"after {delay} second(s)"
            status = Status.PASS
        elif delay is not None:
            delay_detail = f"after {delay} second(s)"
            status = Status.WARN
        else:
            delay_detail = "(delay unknown)"
            status = Status.PASS

        return CheckResult(
            name="Screen Lock",
            status=status,
            severity=Severity.HIGH,
            description="Check if a password is required after sleep or screensaver.",
            detail=f"Screen lock is enabled — password required {delay_detail}.\n"
                   f"  Source: {mdm['source']}",
            recommendation="" if status == Status.PASS else
                "Set to immediate: System Settings > Lock Screen > Require password... > Immediately",
            raw_output=" | ".join(sources_tried),
        )

    sources_tried.append("profile: no MDM/config profile found")

    # --- Could not determine ---
    return CheckResult(
        name="Screen Lock",
        status=Status.WARN,
        severity=Severity.HIGH,
        description="Check if a password is required after sleep or screensaver.",
        detail="Could not determine screen lock status.\n"
               "  Tried: sysadminctl, MDM managed prefs, config profiles.\n"
               "  Note: Must be run as the logged-in user (not just root).\n"
               "  Verify manually: System Settings > Lock Screen",
        recommendation="Verify manually: System Settings > Lock Screen > Require password... > Immediately",
        raw_output=" | ".join(sources_tried),
    )


def run_checks() -> list[CheckResult]:
    return [check_screen_lock()]
