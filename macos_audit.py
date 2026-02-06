#!/usr/bin/env python3
"""
macOS Security Audit Tool
==========================
A read-only security auditing tool for macOS that checks common security
settings and generates a compliance report.

No system modifications are made. Some checks require admin (sudo)
privileges — these are skipped gracefully when running without sudo,
unless --full is specified.

Usage:
    python3 macos_audit.py                    # standard audit (skips admin-only checks)
    sudo python3 macos_audit.py               # full audit with admin privileges
    python3 macos_audit.py --full             # remind to re-run with sudo if needed
    python3 macos_audit.py --json report.json # also write JSON report
    python3 macos_audit.py --help
"""

import argparse
import logging
import platform
import sys
from types import ModuleType

from checks import (
    antivirus,
    find_my_mac,
    filevault,
    firewall,
    gatekeeper,
    remote_login,
    sharing,
    sip,
    updates,
)
from lib.models import AuditReport, CheckResult, Severity, Status
from lib.output import (
    print_banner,
    print_privilege_notice,
    print_result,
    print_summary,
    print_system_info,
    write_json_report,
)
from lib.util import is_admin, run_cmd

# Ordered list of check modules.
# Each must expose:
#   run_checks() -> list[CheckResult]
#   REQUIRES_ADMIN: bool
CHECK_MODULES: list[tuple[str, ModuleType]] = [
    ("Firewall", firewall),
    ("Gatekeeper", gatekeeper),
    ("FileVault", filevault),
    ("System Integrity Protection", sip),
    ("Software Updates", updates),
    ("Antivirus / Endpoint Protection", antivirus),
    ("Remote Login", remote_login),
    ("Sharing Services", sharing),
    ("Find My Mac", find_my_mac),
]


def _skip_results_for(module: ModuleType, category: str) -> list[CheckResult]:
    """Generate SKIPPED results for every check a module would have run."""
    # Run the checks to discover the names, but catch everything.
    # Instead, we create a single SKIPPED result per admin-required module.
    # We derive check names from the module's run_checks function name list
    # or fall back to the category name.
    names: list[str] = []
    for attr in dir(module):
        if attr.startswith("check_"):
            names.append(attr)

    if not names:
        names = [category]

    results = []
    for name in names:
        friendly = name.replace("check_", "").replace("_", " ").title()
        results.append(CheckResult(
            name=friendly,
            status=Status.SKIPPED,
            severity=Severity.INFO,
            description=f"Skipped — requires admin privileges.",
            detail=f"Skipped (requires sudo). Re-run with: sudo python3 macos_audit.py",
        ))
    return results


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


def run_audit(json_path: str | None = None, full: bool = False) -> AuditReport:
    """Run all audit checks and produce the report."""
    print_banner()

    admin = is_admin()
    print_privilege_notice(admin)

    if full and not admin:
        print(
            "\033[91m"
            "  --full was requested but you are not running as admin.\n"
            "  Please re-run with: sudo python3 macos_audit.py --full\n"
            "\033[0m"
        )
        sys.exit(2)

    report = AuditReport()
    report.system_info = gather_system_info()
    report.system_info["Privileges"] = "admin (root)" if admin else "standard user"
    print_system_info(report.system_info)

    for category, module in CHECK_MODULES:
        requires_admin = getattr(module, "REQUIRES_ADMIN", False)

        if requires_admin and not admin:
            # Skip this module — not enough privileges
            print(f"\033[1m▸ {category}\033[0m")
            skipped = _skip_results_for(module, category)
            for result in skipped:
                report.results.append(result)
                print_result(result)
            continue

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
    parser.add_argument(
        "--full",
        action="store_true",
        help="Require a full audit (exit with error if not running as admin)",
    )
    parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Show debug output (plist values read, commands run, sources checked)",
    )
    args = parser.parse_args()

    if args.verbose:
        logging.basicConfig(
            level=logging.DEBUG,
            format="    \033[90m%(name)s: %(message)s\033[0m",
        )

    if platform.system() != "Darwin":
        print(
            "\033[93mWarning: This tool is designed for macOS. "
            "Results will not be accurate on other platforms.\033[0m\n"
        )

    report = run_audit(json_path=args.json, full=args.full)

    # Exit code: 0 if >=80% compliance, 1 otherwise
    sys.exit(0 if report.compliance_pct >= 80 else 1)


if __name__ == "__main__":
    main()
