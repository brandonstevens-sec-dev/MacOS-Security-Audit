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

Commands used (read-only):
  - defaults read /Library/Preferences/com.apple.SoftwareUpdate AutomaticCheckEnabled
  - defaults read /Library/Preferences/com.apple.SoftwareUpdate AutomaticDownload
  - defaults read /Library/Preferences/com.apple.SoftwareUpdate AutomaticallyInstallMacOSUpdates
  - defaults read /Library/Preferences/com.apple.SoftwareUpdate CriticalUpdateInstall
"""

from lib.models import CheckResult, Severity, Status
from lib.util import read_plist_key

_DOMAIN = "/Library/Preferences/com.apple.SoftwareUpdate"


def _check_update_key(key: str, name: str, description: str,
                      severity: Severity, recommendation: str) -> CheckResult:
    """Helper to check a boolean key in the SoftwareUpdate plist."""
    stdout, err = read_plist_key(_DOMAIN, key)

    if stdout is None:
        return CheckResult(
            name=name,
            status=Status.WARN,
            severity=severity,
            description=description,
            detail=f"Could not read setting (may require admin): {err}",
            recommendation=recommendation,
        )

    enabled = stdout.strip() == "1"
    return CheckResult(
        name=name,
        status=Status.PASS if enabled else Status.FAIL,
        severity=severity,
        description=description,
        detail=f"{'Enabled' if enabled else 'Disabled'} (value: {stdout.strip()})",
        recommendation=recommendation if not enabled else "",
        raw_output=stdout,
    )


def check_auto_check() -> CheckResult:
    return _check_update_key(
        key="AutomaticCheckEnabled",
        name="Auto Update Check",
        description="Check if macOS automatically checks for updates.",
        severity=Severity.HIGH,
        recommendation="Enable: System Settings > General > Software Update > Automatic Updates",
    )


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
        name="Auto Install Critical Security Updates",
        description="Check if Rapid Security Responses and critical updates install automatically.",
        severity=Severity.HIGH,
        recommendation="Enable: System Settings > General > Software Update > Automatic Updates > Install Security Responses and system files",
    )


def run_checks() -> list[CheckResult]:
    return [
        check_auto_check(),
        check_auto_download(),
        check_auto_install(),
        check_critical_updates(),
    ]
