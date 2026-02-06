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

Detection strategy (in priority order per key):
  1. Read /Library/Managed Preferences/com.apple.SoftwareUpdate (MDM-enforced)
  2. Read /Library/Preferences/com.apple.SoftwareUpdate (local user settings)
  3. If key is absent from both → treat as enabled (macOS default)

Key notes for modern macOS (Tahoe 26+):
  - AutomaticCheckEnabled is DEPRECATED on macOS 26. Apple no longer writes
    this key; it returns an empty string. We skip it entirely and infer
    the check-for-updates state from the other sub-settings and from
    `softwareupdate --schedule`.
  - The entire com.apple.SoftwareUpdate payload is being migrated to
    Declarative Device Management (DDM). Legacy plist keys for download,
    install, and critical updates still work for now.
  - Keys that DO NOT EXIST default to ENABLED on fresh installs.
  - On macOS 15.4+, Apple forcibly re-enables auto-update settings after
    each OS update.

Commands used (read-only):
  - defaults read /Library/Managed Preferences/com.apple.SoftwareUpdate <key>
  - defaults read /Library/Preferences/com.apple.SoftwareUpdate <key>
  - defaults read /Library/Preferences/com.apple.commerce AutoUpdate
  - softwareupdate --schedule  (fallback signal)
"""

import logging
from dataclasses import dataclass
from typing import Optional

from lib.models import CheckResult, Severity, Status
from lib.util import PlistValue, read_plist_key_full, run_cmd

log = logging.getLogger(__name__)

REQUIRES_ADMIN = False

_MANAGED_DOMAIN = "/Library/Managed Preferences/com.apple.SoftwareUpdate"
_LOCAL_DOMAIN = "/Library/Preferences/com.apple.SoftwareUpdate"
_COMMERCE_DOMAIN = "/Library/Preferences/com.apple.commerce"


@dataclass
class _SubCheck:
    """Result of reading one auto-update sub-setting."""
    label: str
    enabled: Optional[bool]
    source: str  # debug breadcrumb showing where the value came from


def _read_setting(domain_managed: str, domain_local: str,
                  key: str, label: str) -> _SubCheck:
    """Read a boolean auto-update key from managed prefs then local prefs."""
    # 1. MDM managed preferences (takes precedence)
    managed = read_plist_key_full(domain_managed, key)
    if managed.exists:
        log.debug("  %s: managed=%r", key, managed.value)
        return _SubCheck(label=label, enabled=managed.as_bool,
                         source=f"managed: {managed.value!r} [MDM-enforced]")

    # 2. Local preferences
    local = read_plist_key_full(domain_local, key)
    if local.error:
        log.debug("  %s: local error=%s", key, local.error)
        return _SubCheck(label=label, enabled=None,
                         source=f"error ({local.error})")

    if local.exists:
        val = local.as_bool
        if val is not None:
            log.debug("  %s: local=%r -> %s", key, local.value, val)
            return _SubCheck(label=label, enabled=val,
                             source=f"local: {local.value!r}")
        # Key exists but value is empty/unparseable (e.g. deprecated key)
        log.debug("  %s: local=%r -> unparseable, treating as absent", key, local.value)

    # 3. Key not set (or unparseable) → macOS default is enabled
    log.debug("  %s: not set, macOS defaults to enabled", key)
    return _SubCheck(label=label, enabled=True,
                     source="not set (macOS default: enabled)")


def _read_softwareupdate_schedule() -> Optional[bool]:
    """Cross-reference with `softwareupdate --schedule`."""
    stdout, err = run_cmd(["softwareupdate", "--schedule"])
    output = stdout or err or ""
    if not output:
        return None
    log.debug("  softwareupdate --schedule: %r", output)
    if "is on" in output.lower():
        return True
    if "is off" in output.lower():
        return False
    return None


def check_automatic_updates() -> CheckResult:
    """Consolidated check for all automatic software update settings.

    Reads each sub-setting, shows per-component status, and produces
    a single PASS/WARN/FAIL based on overall posture.

    Sub-settings checked:
      - AutomaticDownload (download new updates)
      - CriticalUpdateInstall (Rapid Security Responses)
      - ConfigDataInstall (system data files & security updates)
      - AutomaticallyInstallMacOSUpdates (install macOS updates)
      - AutoUpdate in com.apple.commerce (App Store app updates)

    AutomaticCheckEnabled is deliberately SKIPPED — it is deprecated on
    macOS 26 (Tahoe) and redundant: if any sub-feature is enabled, the
    system must be checking for updates.
    """
    subs = [
        _read_setting(_MANAGED_DOMAIN, _LOCAL_DOMAIN,
                      "AutomaticDownload", "Download new updates"),
        _read_setting(_MANAGED_DOMAIN, _LOCAL_DOMAIN,
                      "CriticalUpdateInstall", "Security Responses & critical updates"),
        _read_setting(_MANAGED_DOMAIN, _LOCAL_DOMAIN,
                      "ConfigDataInstall", "System data files & security updates"),
        _read_setting(_MANAGED_DOMAIN, _LOCAL_DOMAIN,
                      "AutomaticallyInstallMacOSUpdates", "Install macOS updates"),
        _read_setting("/Library/Managed Preferences/com.apple.commerce",
                      _COMMERCE_DOMAIN,
                      "AutoUpdate", "App Store app updates"),
    ]

    # Also check softwareupdate --schedule as a top-level signal
    schedule = _read_softwareupdate_schedule()

    # Build sub-status lines
    detail_lines = []
    enabled_count = 0
    critical_ok = True  # tracks the two most important settings

    for sub in subs:
        if sub.enabled is True:
            icon = "\033[92m✓\033[0m"
            enabled_count += 1
        elif sub.enabled is False:
            icon = "\033[91m✗\033[0m"
        else:
            icon = "\033[93m?\033[0m"

        detail_lines.append(f"  {icon} {sub.label}: {sub.source}")

    # Add schedule cross-reference line
    if schedule is not None:
        sched_icon = "\033[92m✓\033[0m" if schedule else "\033[91m✗\033[0m"
        sched_label = "on" if schedule else "off"
        detail_lines.append(f"  {sched_icon} Check for updates: schedule {sched_label} (softwareupdate --schedule)")

    # Determine overall status
    # Critical: AutomaticDownload + CriticalUpdateInstall
    critical_subs = subs[:2]  # download + critical updates
    critical_ok = all(s.enabled is True for s in critical_subs)
    all_ok = all(s.enabled is True for s in subs)
    any_failed = any(s.enabled is False for s in subs)

    if all_ok:
        status = Status.PASS
        summary = "All automatic update settings are enabled."
    elif critical_ok:
        status = Status.PASS
        summary = "Critical update settings enabled. Some optional settings are off."
    elif any_failed:
        status = Status.FAIL
        summary = f"{enabled_count}/{len(subs)} update settings enabled."
    else:
        status = Status.WARN
        summary = f"Could not fully determine update settings ({enabled_count}/{len(subs)} confirmed)."

    # If schedule explicitly disagrees with our finding, downgrade to WARN
    if schedule is False and status == Status.PASS:
        status = Status.WARN
        summary += " (but softwareupdate --schedule reports checking is off)"

    detail = summary + "\n" + "\n".join(detail_lines)

    raw_parts = [f"{s.label}: {s.source}" for s in subs]
    if schedule is not None:
        raw_parts.append(f"schedule: {'on' if schedule else 'off'}")

    return CheckResult(
        name="Automatic Updates",
        status=status,
        severity=Severity.HIGH,
        description="Check if macOS automatic software updates are enabled.",
        detail=detail,
        recommendation="Enable: System Settings > General > Software Update > Automatic Updates",
        raw_output=" | ".join(raw_parts),
    )


def run_checks() -> list[CheckResult]:
    return [check_automatic_updates()]
