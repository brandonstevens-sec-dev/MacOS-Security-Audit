# macOS Security Audit Tool

A read-only Python CLI tool that audits key macOS security settings and generates a compliance report. Inspired by [mr-r3b00t/windows_audit](https://github.com/mr-r3b00t/windows_audit).

**No system modifications are made.** All checks use read-only macOS commands.

## Download

A pre-built macOS app is available on the
[Releases page](https://github.com/brandonstevens-sec-dev/MacOS-Security-Audit/releases)
for users who don't want to build from source. Python 3.12 must be installed on
your Mac (the app bundles the audit scripts but not a Python runtime).

> **Note:** The app is unsigned. On first launch macOS Gatekeeper will block it.
> To open it, right-click the app and choose **Open**, or go to
> **System Settings > Privacy & Security > Open Anyway**.

## Requirements

- macOS 13 (Ventura) or later (tested on macOS with Apple Silicon)
- Python 3.10+ (3.12 recommended)
- No third-party dependencies — uses only the Python standard library

## Quick Start

```bash
git clone https://github.com/brandonstevens-sec-dev/MacOS-Security-Audit.git
cd MacOS-Security-Audit
python3.12 -m venv venv
source venv/bin/activate
chmod +x macos_audit.py
./macos_audit.py
```

Some checks (Remote Login, Find My Mac) require admin privileges and will be
**skipped** when running without sudo. To run a complete audit:

```bash
sudo ./macos_audit.py
```

### Troubleshooting

- **Multiple Python versions installed?** Use `python3.12` explicitly instead of
  `python3`, which may point to an older version. Check with `python3 --version`.
- **`command not found: python3.12`?** Install via [python.org](https://www.python.org/downloads/)
  or Homebrew: `brew install python@3.12`
- **Permission denied running `./macos_audit.py`?** Run `chmod +x macos_audit.py` first,
  or invoke directly with `python3.12 macos_audit.py`.
- **Virtual environment not activating?** Make sure you run `source venv/bin/activate`
  (not just `venv/bin/activate`). Your prompt should show `(venv)` when active.

## Usage

```
./macos_audit.py [OPTIONS]

Options:
  --json FILE    Write results to a JSON file in addition to terminal output
  --full         Require admin privileges; exit with error if not running as root
  --verbose, -v  Show debug output (plist values read, commands run)
  --help         Show help message
```

### Examples

Standard audit (admin-only checks are skipped gracefully):
```bash
./macos_audit.py
```

Full audit with admin privileges:
```bash
sudo ./macos_audit.py
```

Enforce full audit (fails fast if not root):
```bash
sudo ./macos_audit.py --full
```

Terminal output plus JSON report:
```bash
./macos_audit.py --json audit_report.json
```

## What Gets Checked

| Check | Command(s) | Severity | Why It Matters | Admin? |
|-------|-----------|----------|----------------|--------|
| **Firewall Enabled** | `socketfilterfw --getglobalstate` | High | Blocks unauthorized inbound connections | No |
| **Firewall Stealth Mode** | `socketfilterfw --getstealthmode` | Medium | Hides the machine from network probes | No |
| **Gatekeeper** | `spctl --status` | Critical | Prevents unsigned/tampered app execution | No |
| **FileVault Encryption** | `fdesetup status` | Critical | Protects data at rest on disk | No |
| **System Integrity Protection** | `csrutil status` | Critical | Protects system files from modification | No |
| **Automatic Updates** | `defaults read` SoftwareUpdate + commerce | High | Ensures all update components are enabled | No |
| **Antivirus / Endpoint Protection** | `/Applications`, `ps`, LaunchDaemons | Medium | Detects third-party security software | No |
| **Remote Login (SSH)** | `systemsetup -getremotelogin` | High | SSH server increases attack surface | Yes |
| **File Sharing (SMB)** | `launchctl list com.apple.smbd` | Medium | Exposes filesystem over the network | No |
| **Screen Sharing** | `launchctl list com.apple.screensharing` | Medium | Allows remote GUI control | No |
| **Find My Mac** | `defaults read` FindMyMac | Medium | Enables remote locate/lock/wipe | Yes |

The **Automatic Updates** check is a consolidated check that verifies 5 sub-settings:
auto-download, security responses, system data files, macOS updates, and App Store updates.
It also cross-references with `softwareupdate --schedule`. The deprecated `AutomaticCheckEnabled`
key (empty on macOS 26 Tahoe) is skipped — it is redundant when sub-features are enabled.

The **Antivirus / Endpoint Protection** check scans for 13 common security products
(Malwarebytes, CrowdStrike Falcon, SentinelOne, etc.) using three methods: application
bundles in `/Applications`, running processes, and LaunchDaemon/LaunchAgent plists.
If no third-party AV is found, it reports `[INFO]` noting that built-in macOS protections
(XProtect, Gatekeeper, MRT) may be sufficient for personal use.

## Output

### Terminal

The tool prints color-coded results:
- **Green `[PASS]`** — setting meets security best practice
- **Red `[FAIL]`** — setting does not meet security best practice
- **Yellow `[WARN]`** — setting is borderline or could not be fully verified
- **Blue `[INFO]`** — informational finding (not scored in compliance %)
- **Cyan `[SKIP]`** — check was skipped (requires admin privileges)
- **Gray `[ERR ]`** — check encountered an error (e.g., command not found)

A privilege notice is printed at startup indicating whether admin checks will
run or be skipped. The compliance summary at the end excludes skipped and
errored checks from the percentage calculation.

### JSON

When `--json` is specified, a structured JSON file is written containing:
- System information (including privilege level)
- Summary statistics (total, passed, failed, warnings, skipped, errors, compliance %)
- Full result details for each check

### Exit Codes

- `0` — compliance percentage >= 80%
- `1` — compliance percentage < 80%
- `2` — `--full` was requested but not running as admin

This allows integration with CI/CD or automated compliance checking.

## GUI Version (SwiftUI)

A native macOS GUI is included. The easiest way to use it is to download the
pre-built `.app` from the
[Releases page](https://github.com/brandonstevens-sec-dev/MacOS-Security-Audit/releases).

### Using the Pre-built App

1. Download `MacOSAuditGUI.app.zip` from the latest release
2. Unzip and move to `/Applications` (or run from anywhere)
3. Right-click the app and choose **Open** (required on first launch — the app is unsigned)
4. Click **Run Security Audit**

The app bundles the Python audit scripts internally. You only need Python 3.12
installed on your Mac.

### Building from Source (Development)

If you want to modify the GUI or contribute:

1. Set up the Python CLI first (see Quick Start above)
2. Open the Xcode project:
   ```bash
   open MacOSAuditGUI/MacOSAuditGUI.xcodeproj
   ```
3. Select the **MacOSAuditGUI** scheme and click **Run** (or press `Cmd+R`)

The Xcode project references `macos_audit.py`, `checks/`, and `lib/` from the
repo root and bundles them into the app's Resources directory at build time.

### How It Works

- The GUI runs `macos_audit.py --json <tmpfile>` as a subprocess
- Parses the JSON output and displays results with colored status indicators
- Shows a compliance score summary and expandable detail for each check
- Export results as JSON via the toolbar export button
- Admin-only checks show as skipped when not running with sudo

### CLI vs GUI

| | CLI | GUI |
|---|---|---|
| **Install** | `git clone` + `pip` | Download `.app` from Releases |
| **Run** | `./macos_audit.py` | Double-click the app |
| **Output** | Terminal (colored text) | Native macOS window |
| **JSON export** | `--json report.json` | Toolbar export button |
| **sudo support** | `sudo ./macos_audit.py` | Run from Terminal with sudo |
| **Dependencies** | Python 3.10+ | Python 3.12 (no Xcode needed) |
| **Development** | Edit `.py` files | Xcode 15+ required |

## Project Structure

```
MacOS-Security-Audit/
├── macos_audit.py              # CLI entry point
├── checks/                     # Security check modules
│   ├── firewall.py             # Application Firewall & stealth mode
│   ├── gatekeeper.py           # Gatekeeper code-signing enforcement
│   ├── filevault.py            # FileVault full-disk encryption
│   ├── sip.py                  # System Integrity Protection
│   ├── updates.py              # Automatic software update settings
│   ├── antivirus.py            # Third-party antivirus / endpoint protection
│   ├── remote_login.py         # SSH server status
│   ├── sharing.py              # File Sharing & Screen Sharing
│   └── find_my_mac.py          # Find My Mac / Activation Lock
├── lib/                        # Core framework
│   ├── models.py               # CheckResult, AuditReport data models
│   ├── output.py               # Terminal formatting & JSON export
│   └── util.py                 # Command execution helpers
├── MacOSAuditGUI/              # Native macOS GUI (SwiftUI)
│   ├── MacOSAuditGUI.xcodeproj
│   └── MacOSAuditGUI/
│       ├── MacOSAuditGUIApp.swift   # App entry point
│       ├── ContentView.swift        # Main window layout
│       ├── CheckRowView.swift       # Individual check result row
│       ├── SummaryView.swift        # Compliance score summary
│       ├── AuditModels.swift        # Swift models matching JSON output
│       └── AuditRunner.swift        # Subprocess execution & JSON parsing
└── README.md
```

Each check module contains:
- A docstring explaining what is checked and why it matters
- A `REQUIRES_ADMIN` boolean indicating if the check needs sudo
- Individual check functions returning `CheckResult` objects
- A `run_checks()` function that returns all results for that module

## Adding New Checks

1. Create a new file in `checks/` (e.g., `checks/bluetooth.py`)
2. Add `REQUIRES_ADMIN = True` or `REQUIRES_ADMIN = False`
3. Implement check functions returning `CheckResult` objects
4. Add a `run_checks()` function that returns a list of results
5. Register the module in `CHECK_MODULES` in `macos_audit.py`

## Releases

### v1.0 — February 2026

- Initial release
- Native SwiftUI GUI included (pre-built `.app` available on Releases page)
- CLI supports JSON export and exit codes for CI/CD integration
- 11 security checks across firewall, encryption, updates, antivirus, and sharing services
- Privilege-aware: runs without sudo (admin-only checks skipped gracefully)
- Tested on macOS 26.2 Tahoe (Apple Silicon M4)

## Disclaimer

This tool is provided as-is for security assessment purposes. It performs
**read-only** operations and does not modify any system settings. Results should
be validated manually. Use at your own risk.

The macOS GUI app is **unsigned** and not notarized by Apple. On first launch,
macOS Gatekeeper will display a warning. To open it, right-click the app and
choose **Open**, or go to **System Settings > Privacy & Security > Open Anyway**.

## License

MIT
