#!/usr/bin/env python3
"""
macOS Security Audit Tool
==========================
A read-only security auditing tool for macOS that checks common security
settings and generates a compliance report.

No system modifications are made. Some checks may require admin (sudo)
privileges for full accuracy.

Usage:
    python3 macos_audit.py                    # colored terminal output
    python3 macos_audit.py --json report.json # also write JSON report
    python3 macos_audit.py --help
"""

import argparse
import platform
import sys

from checks import (
    find_my_mac,
    filevault,
    firewall,
    gatekeeper,
    remote_login,
    screen_lock,
    sharing,
    sip,
    updates,
)
from lib.models import AuditReport
from lib.output import (
    print_banner,
    print_result,
    print_summary,
    print_system_info,
    write_json_report,
)
from lib.util import run_cmd

# Ordered list of check modules. Each must expose a run_checks() -> list[CheckResult].
CHECK_MODULES = [
    ("Firewall", firewall),
    ("Gatekeeper", gatekeeper),
    ("FileVault", filevault),
    ("System Integrity Protection", sip),
    ("Software Updates", updates),
    ("Screen Lock", screen_lock),
    ("Remote Login", remote_login),
    ("Sharing Services", sharing),
    ("Find My Mac", find_my_mac),
]


def gather_system_info() -> dict:
    """Collect basic system information for the report header."""
    info = {
        "Hostname": platform.node(),
        "OS": f"macOS {platform.mac_ver()[0] or 'Unknown'}",
        "Architecture": platform.machine(),
        "Kernel": platform.release(),
    }

    # Get hardware model
    hw_out, _ = run_cmd(["sysctl", "-n", "hw.model"])
    if hw_out:
        info["Hardware Model"] = hw_out

    # Get macOS build
    build_out, _ = run_cmd(["sw_vers", "-buildVersion"])
    if build_out:
        info["Build"] = build_out

    return info


def run_audit(json_path: str | None = None) -> AuditReport:
    """Run all audit checks and produce the report."""
    print_banner()

    report = AuditReport()
    report.system_info = gather_system_info()
    print_system_info(report.system_info)

    for category, module in CHECK_MODULES:
        print(f"\033[1m▸ {category}\033[0m")
        results = module.run_checks()
        for result in results:
            report.results.append(result)
            print_result(result)

    print_summary(report)

    if json_path:
        write_json_report(report, json_path)

    return report


def main() -> None:
    parser = argparse.ArgumentParser(
        description="macOS Security Audit Tool — read-only security checks",
    )
    parser.add_argument(
        "--json",
        metavar="FILE",
        help="Write results to a JSON file",
    )
    args = parser.parse_args()

    if platform.system() != "Darwin":
        print(
            "\033[93mWarning: This tool is designed for macOS. "
            "Results will not be accurate on other platforms.\033[0m\n"
        )

    report = run_audit(json_path=args.json)

    # Exit code: 0 if >=80%% compliance, 1 otherwise
    sys.exit(0 if report.compliance_pct >= 80 else 1)


if __name__ == "__main__":
    main()
