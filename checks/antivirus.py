"""
Check: Third-Party Antivirus / Endpoint Protection
=====================================================
Scans for installed third-party antivirus and endpoint security products.

Why it matters:
  - macOS includes built-in protections (XProtect, Gatekeeper, MRT) but
    third-party AV provides additional layers: real-time scanning, behavioral
    analysis, centralized management, and faster signature updates.
  - Enterprise environments typically require endpoint protection agents.
  - For personal use, built-in macOS protections may be sufficient.

Detection strategy:
  1. Scan /Applications for known AV application bundles
  2. Check for running AV processes (ps -eo comm)
  3. Scan LaunchDaemons and LaunchAgents for AV service plists
"""

import logging
import os
import re
from pathlib import Path

from lib.models import CheckResult, Severity, Status
from lib.util import run_cmd

log = logging.getLogger(__name__)

REQUIRES_ADMIN = False

# Known AV/endpoint security products.
# Each entry: (display_name, app_patterns, process_patterns, plist_patterns)
#   app_patterns:     substrings matched against /Applications contents (case-insensitive)
#   process_patterns: substrings matched against running process names (case-insensitive)
#   plist_patterns:   substrings matched against LaunchDaemon/Agent filenames (case-insensitive)
_AV_PRODUCTS = [
    (
        "Malwarebytes",
        ["malwarebytes"],
        ["rtprotectiondaemon", "malwarebytes"],
        ["com.malwarebytes."],
    ),
    (
        "Bitdefender",
        ["bitdefender"],
        ["bdldaemon", "bitdefender"],
        ["com.bitdefender."],
    ),
    (
        "Norton",
        ["norton"],
        ["nortonsecurity", "nortonmonitor"],
        ["com.norton.", "com.symantec."],
    ),
    (
        "Sophos",
        ["sophos"],
        ["sophosscanagent", "sophosd", "sophosautoupdate"],
        ["com.sophos."],
    ),
    (
        "CrowdStrike Falcon",
        ["falcon.app"],
        ["falcond", "falcon-sensor"],
        ["com.crowdstrike."],
    ),
    (
        "ESET",
        ["eset"],
        ["esets_daemon", "esets_proxy", "eset"],
        ["com.eset."],
    ),
    (
        "Avast",
        ["avast"],
        ["com.avast"],
        ["com.avast."],
    ),
    (
        "AVG",
        ["avg antivirus", "avg security"],
        ["com.avg"],
        ["com.avg."],
    ),
    (
        "Trend Micro",
        ["trend micro", "antivirus one"],
        ["icoreservice", "trendmicro"],
        ["com.trendmicro."],
    ),
    (
        "Kaspersky",
        ["kaspersky"],
        ["kav", "kaspersky"],
        ["com.kaspersky."],
    ),
    (
        "SentinelOne",
        ["sentinelone", "sentinel agent"],
        ["sentineld", "sentinelagent"],
        ["com.sentinelone."],
    ),
    (
        "Carbon Black",
        ["carbon black", "vmware carbon black"],
        ["cbdaemon", "cb_defense", "cbagentd", "repmgr"],
        ["com.carbonblack.", "com.vmware.carbonblack."],
    ),
    (
        "Elastic",
        ["elastic"],
        ["elastic-agent", "elastic-endpoint"],
        ["co.elastic."],
    ),
]


def _scan_applications() -> dict[str, str]:
    """Check /Applications for known AV app bundles.

    Returns {product_name: matched_app_path} for each detected product.
    """
    found: dict[str, str] = {}
    apps_dir = Path("/Applications")
    if not apps_dir.is_dir():
        return found

    try:
        entries = [e.name.lower() for e in apps_dir.iterdir()]
    except PermissionError:
        log.debug("  Permission denied reading /Applications")
        return found

    log.debug("  Scanning %d entries in /Applications", len(entries))

    for name, app_patterns, _, _ in _AV_PRODUCTS:
        for pattern in app_patterns:
            for entry in entries:
                if pattern in entry:
                    found[name] = f"/Applications (matched: {entry})"
                    log.debug("  App match: %s → %s", name, entry)
                    break
            if name in found:
                break

    return found


def _scan_processes() -> dict[str, str]:
    """Check running processes for known AV daemons/agents.

    Returns {product_name: matched_process} for each detected product.
    """
    found: dict[str, str] = {}
    stdout, err = run_cmd(["ps", "-eo", "comm"], timeout=10)
    if not stdout:
        log.debug("  Could not list processes: %s", err)
        return found

    procs_lower = stdout.lower()
    log.debug("  Scanning running processes (%d lines)", procs_lower.count("\n") + 1)

    for name, _, proc_patterns, _ in _AV_PRODUCTS:
        for pattern in proc_patterns:
            if pattern in procs_lower:
                found[name] = f"running process (matched: {pattern})"
                log.debug("  Process match: %s → %s", name, pattern)
                break

    return found


def _scan_launch_services() -> dict[str, str]:
    """Check LaunchDaemons and LaunchAgents for known AV service plists.

    Returns {product_name: matched_plist_path} for each detected product.
    """
    found: dict[str, str] = {}

    search_dirs = [
        "/Library/LaunchDaemons",
        "/Library/LaunchAgents",
        os.path.expanduser("~/Library/LaunchAgents"),
    ]

    for search_dir in search_dirs:
        dir_path = Path(search_dir)
        if not dir_path.is_dir():
            continue

        try:
            entries = [e.name.lower() for e in dir_path.iterdir()]
        except PermissionError:
            log.debug("  Permission denied reading %s", search_dir)
            continue

        log.debug("  Scanning %d entries in %s", len(entries), search_dir)

        for name, _, _, plist_patterns in _AV_PRODUCTS:
            if name in found:
                continue
            for pattern in plist_patterns:
                for entry in entries:
                    if pattern in entry:
                        found[name] = f"{search_dir} (matched: {entry})"
                        log.debug("  Plist match: %s → %s in %s", name, entry, search_dir)
                        break
                if name in found:
                    break

    return found


def check_antivirus() -> CheckResult:
    """Detect installed third-party antivirus / endpoint security products."""

    # Run all three detection methods and merge results
    detected: dict[str, list[str]] = {}

    for label, scanner in [
        ("app", _scan_applications),
        ("process", _scan_processes),
        ("service", _scan_launch_services),
    ]:
        for product, source in scanner().items():
            detected.setdefault(product, []).append(source)

    if detected:
        product_lines = []
        for product, sources in sorted(detected.items()):
            product_lines.append(f"  \033[92m✓\033[0m {product}")
            for src in sources:
                product_lines.append(f"      detected via: {src}")

        detail = (
            f"Third-party security software detected ({len(detected)} product(s)):\n"
            + "\n".join(product_lines)
        )

        return CheckResult(
            name="Antivirus / Endpoint Protection",
            status=Status.PASS,
            severity=Severity.MEDIUM,
            description="Check for installed third-party antivirus or endpoint security software.",
            detail=detail,
        )

    # No third-party AV found
    return CheckResult(
        name="Antivirus / Endpoint Protection",
        status=Status.INFO,
        severity=Severity.LOW,
        description="Check for installed third-party antivirus or endpoint security software.",
        detail=(
            "No third-party antivirus detected — relying on built-in macOS protections.\n"
            "  Built-in: XProtect, Gatekeeper, MRT (Malware Removal Tool)\n"
            "  Note: Built-in protections may be sufficient for personal use."
        ),
    )


def run_checks() -> list[CheckResult]:
    return [check_antivirus()]
