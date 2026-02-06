"""
Check: Find My Mac
====================
Find My Mac allows a user to locate, lock, or erase their Mac remotely via
iCloud. It also enables Activation Lock, which prevents anyone from
reactivating a stolen Mac without the owner's Apple ID credentials.

Why it matters:
  - Enables remote wipe if the device is lost or stolen
  - Activation Lock deters theft by making stolen hardware unusable
  - Required by many enterprise security policies

Commands used (read-only):
  - defaults read /Library/Preferences/com.apple.FindMyMac FMMEnabled
  - nvram -x -p (look for fmm-mobileme-token as a secondary indicator)
"""

from lib.models import CheckResult, Severity, Status
from lib.util import read_plist_key, run_cmd


def check_find_my_mac() -> CheckResult:
    """Check whether Find My Mac is enabled."""
    # Primary check: FMMEnabled plist key
    stdout, err = read_plist_key(
        "/Library/Preferences/com.apple.FindMyMac", "FMMEnabled"
    )

    if stdout is not None:
        enabled = stdout.strip() == "1"
        return CheckResult(
            name="Find My Mac",
            status=Status.PASS if enabled else Status.FAIL,
            severity=Severity.MEDIUM,
            description="Check if Find My Mac is enabled for remote locate/wipe.",
            detail=f"Find My Mac is {'enabled' if enabled else 'disabled'}.",
            recommendation="" if enabled else "Enable: System Settings > Apple ID > iCloud > Find My Mac",
            raw_output=stdout,
        )

    # Secondary check: look for fmm-mobileme-token in NVRAM
    nvram_out, nvram_err = run_cmd(["nvram", "-x", "-p"])
    if nvram_out and "fmm-mobileme-token" in nvram_out:
        return CheckResult(
            name="Find My Mac",
            status=Status.PASS,
            severity=Severity.MEDIUM,
            description="Check if Find My Mac is enabled for remote locate/wipe.",
            detail="Find My Mac appears enabled (NVRAM token present).",
        )

    # Could not determine
    return CheckResult(
        name="Find My Mac",
        status=Status.WARN,
        severity=Severity.MEDIUM,
        description="Check if Find My Mac is enabled for remote locate/wipe.",
        detail="Could not determine Find My Mac status. Check may require admin privileges or an active iCloud account.",
        recommendation="Verify manually: System Settings > Apple ID > iCloud > Find My Mac",
    )


def run_checks() -> list[CheckResult]:
    return [check_find_my_mac()]
