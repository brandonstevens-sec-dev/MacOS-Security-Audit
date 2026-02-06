"""
Check: Automatic Software Updates
===================================
macOS can be configured to automatically check for, download, and install
system updates, app updates, and critical security patches (XProtect,
Rapid Security Responses).

Why it matters:
  - Unpatched systems are the #1 attack vector for known exploits
  - Automatic updates ensure security patches are applied promptly
  - macOS security updates include XProtect definitions, MRT removals,
    and Rapid Security Responses that patch actively-exploited vulns

Detection strategy (in priority order):
  1. Read /Library/Managed Preferences/com.apple.SoftwareUpdate (MDM-enforced,
     overrides local settings — checked first)
  2. Read /Library/Preferences/com.apple.SoftwareUpdate (local user settings)
  3. For AutomaticCheckEnabled only: cross-reference with
     `softwareupdate --schedule` as a fallback

Key behavior on modern macOS:
  - Keys that DO NOT EXIST in the plist default to ENABLED on fresh installs.
    Apple ships macOS with auto-updates on; the plist key is only written when
    a user or MDM explicitly changes the setting.
  - `defaults read` returns "1"/"0" for booleans (not "true"/"false"),
    but we handle both for robustness.
  - On macOS 15.4+, Apple forcibly re-enables all auto-update settings
    after each OS update.

Commands used (read-only):
  - defaults read /Library/Managed Preferences/com.apple.SoftwareUpdate <key>
  - defaults read /Library/Preferences/com.apple.SoftwareUpdate <key>
  - defaults read /Library/Preferences/com.apple.commerce AutoUpdate
  - softwareupdate --schedule  (fallback for AutomaticCheckEnabled)
"""

import logging
from typing import Optional

from lib.models import CheckResult, Severity, Status
from lib.util import PlistValue, read_plist_key_full, run_cmd

log = logging.getLogger(__name__)

REQUIRES_ADMIN = False

_MANAGED_DOMAIN = "/Library/Managed Preferences/com.apple.SoftwareUpdate"
_LOCAL_DOMAIN = "/Library/Preferences/com.apple.SoftwareUpdate"
_COMMERCE_DOMAIN = "/Library/Preferences/com.apple.commerce"


def _read_update_setting(key: str) -> tuple[Optional[bool], str]:
    """Read an auto-update boolean from managed prefs, then local prefs.

    Returns (value_or_None, debug_detail_string).
    """
    sources_tried = []

    # 1. Check MDM managed preferences (takes precedence)
    managed = read_plist_key_full(_MANAGED_DOMAIN, key)
    if managed.error:
        sources_tried.append(f"managed: error ({managed.error})")
    elif managed.exists:
        sources_tried.append(f"managed: {managed.value!r}")
        log.debug("  %s: managed pref exists = %r", key, managed.value)
        return managed.as_bool, " | ".join(sources_tried) + " [MDM-enforced]"
    else:
        sources_tried.append("managed: not set")

    # 2. Check local preferences
    local = read_plist_key_full(_LOCAL_DOMAIN, key)
    if local.error:
        sources_tried.append(f"local: error ({local.error})")
        log.debug("  %s: local pref error = %s", key, local.error)
        return None, " | ".join(sources_tried)
    elif local.exists:
        sources_tried.append(f"local: {local.value!r}")
        log.debug("  %s: local pref exists = %r", key, local.value)
        return local.as_bool, " | ".join(sources_tried)
    else:
        sources_tried.append("local: not set (defaults to enabled)")
        log.debug("  %s: key not in plist, macOS defaults to enabled", key)
        return True, " | ".join(sources_tried)


def _check_update_key(key: str, name: str, description: str,
                      severity: Severity, recommendation: str) -> CheckResult:
    """Check a boolean auto-update key across managed and local plists."""
    enabled, debug_info = _read_update_setting(key)
    log.debug("  %s → enabled=%s debug=%s", name, enabled, debug_info)

    if enabled is None:
        return CheckResult(
            name=name,
            status=Status.WARN,
            severity=severity,
            description=description,
            detail=f"Could not determine setting. [{debug_info}]",
            recommendation=recommendation,
            raw_output=debug_info,
        )

    if enabled:
        detail = f"Enabled [{debug_info}]"
    else:
        detail = f"Disabled [{debug_info}]"

    return CheckResult(
        name=name,
        status=Status.PASS if enabled else Status.FAIL,
        severity=severity,
        description=description,
        detail=detail,
        recommendation=recommendation if not enabled else "",
        raw_output=debug_info,
    )


def check_auto_check() -> CheckResult:
    """Check if macOS automatically checks for updates.

    Also cross-references with `softwareupdate --schedule` as a fallback.
    """
    result = _check_update_key(
        key="AutomaticCheckEnabled",
        name="Auto Update Check",
        description="Check if macOS automatically checks for updates.",
        severity=Severity.HIGH,
        recommendation="Enable: System Settings > General > Software Update > Automatic Updates",
    )

    # Cross-reference with softwareupdate --schedule for extra confidence
    sw_stdout, sw_err = run_cmd(["softwareupdate", "--schedule"])
    sw_output = sw_stdout or sw_err or ""
    if sw_output:
        log.debug("  softwareupdate --schedule: %r", sw_output)
        schedule_on = "is on" in sw_output.lower()
        result.raw_output = (result.raw_output or "") + f" | schedule: {sw_output}"

        # If plist said enabled but schedule says off (or vice versa), warn
        plist_passed = result.status == Status.PASS
        if plist_passed and not schedule_on:
            result.status = Status.WARN
            result.detail += f" (but softwareupdate --schedule reports: {sw_output})"
        elif not plist_passed and schedule_on:
            result.status = Status.WARN
            result.detail += f" (but softwareupdate --schedule reports: {sw_output})"

    return result


def check_auto_download() -> CheckResult:
    return _check_update_key(
        key="AutomaticDownload",
        name="Auto Update Download",
        description="Check if macOS automatically downloads available updates.",
        severity=Severity.MEDIUM,
        recommendation="Enable: System Settings > General > Software Update > Automatic Updates > Download new updates when available",
    )


def check_auto_install() -> CheckResult:
    return _check_update_key(
        key="AutomaticallyInstallMacOSUpdates",
        name="Auto Install macOS Updates",
        description="Check if macOS automatically installs system updates.",
        severity=Severity.MEDIUM,
        recommendation="Enable: System Settings > General > Software Update > Automatic Updates > Install macOS updates",
    )


def check_critical_updates() -> CheckResult:
    return _check_update_key(
        key="CriticalUpdateInstall",
        name="Auto Install Security Updates",
        description="Check if Rapid Security Responses and critical updates install automatically.",
        severity=Severity.HIGH,
        recommendation="Enable: System Settings > General > Software Update > Automatic Updates > Install Security Responses and system files",
    )


def check_config_data_install() -> CheckResult:
    return _check_update_key(
        key="ConfigDataInstall",
        name="Auto Install System Data Files",
        description="Check if system data files and security updates install automatically.",
        severity=Severity.HIGH,
        recommendation="Enable: System Settings > General > Software Update > Automatic Updates > Install Security Responses and system files",
    )


def check_app_store_auto_update() -> CheckResult:
    """Check if App Store apps are updated automatically.

    This uses a different plist domain: com.apple.commerce.
    """
    managed = read_plist_key_full(
        "/Library/Managed Preferences/com.apple.commerce", "AutoUpdate"
    )
    local = read_plist_key_full(_COMMERCE_DOMAIN, "AutoUpdate")

    sources_tried = []

    if managed.exists:
        sources_tried.append(f"managed: {managed.value!r}")
        enabled = managed.as_bool
        debug_info = " | ".join(sources_tried) + " [MDM-enforced]"
    elif managed.error:
        sources_tried.append(f"managed: error ({managed.error})")
        if local.exists:
            sources_tried.append(f"local: {local.value!r}")
            enabled = local.as_bool
        elif local.error:
            sources_tried.append(f"local: error ({local.error})")
            enabled = None
        else:
            sources_tried.append("local: not set (defaults to enabled)")
            enabled = True
        debug_info = " | ".join(sources_tried)
    elif local.exists:
        sources_tried.append("managed: not set")
        sources_tried.append(f"local: {local.value!r}")
        enabled = local.as_bool
        debug_info = " | ".join(sources_tried)
    elif local.error:
        sources_tried.append("managed: not set")
        sources_tried.append(f"local: error ({local.error})")
        enabled = None
        debug_info = " | ".join(sources_tried)
    else:
        sources_tried.append("managed: not set")
        sources_tried.append("local: not set (defaults to enabled)")
        enabled = True
        debug_info = " | ".join(sources_tried)

    log.debug("  App Store AutoUpdate → enabled=%s debug=%s", enabled, debug_info)

    if enabled is None:
        return CheckResult(
            name="App Store Auto Update",
            status=Status.WARN,
            severity=Severity.LOW,
            description="Check if App Store apps are updated automatically.",
            detail=f"Could not determine setting. [{debug_info}]",
            recommendation="Enable: System Settings > General > Software Update > Automatic Updates > Install App updates from the App Store",
            raw_output=debug_info,
        )

    return CheckResult(
        name="App Store Auto Update",
        status=Status.PASS if enabled else Status.FAIL,
        severity=Severity.LOW,
        description="Check if App Store apps are updated automatically.",
        detail=f"{'Enabled' if enabled else 'Disabled'} [{debug_info}]",
        recommendation="" if enabled else "Enable: System Settings > General > Software Update > Automatic Updates > Install App updates from the App Store",
        raw_output=debug_info,
    )


def run_checks() -> list[CheckResult]:
    return [
        check_auto_check(),
        check_auto_download(),
        check_auto_install(),
        check_critical_updates(),
        check_config_data_install(),
        check_app_store_auto_update(),
    ]
