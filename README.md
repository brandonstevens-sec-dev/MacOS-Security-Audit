# macOS Security Audit Tool

A read-only Python CLI tool that audits key macOS security settings and generates a compliance report. Inspired by [mr-r3b00t/windows_audit](https://github.com/mr-r3b00t/windows_audit).

**No system modifications are made.** All checks use read-only macOS commands.

## Requirements

- macOS 13 (Ventura) or later (tested on macOS with Apple Silicon)
- Python 3.10+
- No third-party dependencies — uses only the Python standard library

## Quick Start

```bash
git clone https://github.com/brandonstevens-sec-dev/MacOS-Security-Audit.git
cd MacOS-Security-Audit
python3 macos_audit.py
```

Some checks (Remote Login, Find My Mac) require admin privileges and will be
**skipped** when running without sudo. To run a complete audit:

```bash
sudo python3 macos_audit.py
```

## Usage

```
python3 macos_audit.py [OPTIONS]

Options:
  --json FILE    Write results to a JSON file in addition to terminal output
  --full         Require admin privileges; exit with error if not running as root
  --verbose, -v  Show debug output (plist values read, commands run)
  --help         Show help message
```

### Examples

Standard audit (admin-only checks are skipped gracefully):
```bash
python3 macos_audit.py
```

Full audit with admin privileges:
```bash
sudo python3 macos_audit.py
```

Enforce full audit (fails fast if not root):
```bash
sudo python3 macos_audit.py --full
```

Terminal output plus JSON report:
```bash
python3 macos_audit.py --json audit_report.json
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
| **Screen Lock** | `sysadminctl -screenLock` | High | Prevents unauthorized physical access | No |
| **Remote Login (SSH)** | `systemsetup -getremotelogin` | High | SSH server increases attack surface | Yes |
| **File Sharing (SMB)** | `launchctl list com.apple.smbd` | Medium | Exposes filesystem over the network | No |
| **Screen Sharing** | `launchctl list com.apple.screensharing` | Medium | Allows remote GUI control | No |
| **Find My Mac** | `defaults read` FindMyMac | Medium | Enables remote locate/lock/wipe | Yes |

The **Automatic Updates** check is a consolidated check that verifies 5 sub-settings:
auto-download, security responses, system data files, macOS updates, and App Store updates.
It also cross-references with `softwareupdate --schedule`. The deprecated `AutomaticCheckEnabled`
key (empty on macOS 26 Tahoe) is skipped — it is redundant when sub-features are enabled.

The **Screen Lock** check uses `sysadminctl -screenLock status` as the primary detection method,
with MDM managed preferences and configuration profiles as fallbacks. The deprecated
`askForPassword` plist key (empty since macOS 10.13) is not used. The check reports both
the enabled/disabled state and the password delay (immediate, seconds, or unknown).

## Output

### Terminal

The tool prints color-coded results:
- **Green `[PASS]`** — setting meets security best practice
- **Red `[FAIL]`** — setting does not meet security best practice
- **Yellow `[WARN]`** — setting is borderline or could not be fully verified
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

## Project Structure

```
MacOS-Security-Audit/
├── macos_audit.py          # CLI entry point
├── checks/                 # Security check modules
│   ├── firewall.py         # Application Firewall & stealth mode
│   ├── gatekeeper.py       # Gatekeeper code-signing enforcement
│   ├── filevault.py        # FileVault full-disk encryption
│   ├── sip.py              # System Integrity Protection
│   ├── updates.py          # Automatic software update settings
│   ├── screen_lock.py      # Screen lock & password requirements
│   ├── remote_login.py     # SSH server status
│   ├── sharing.py          # File Sharing & Screen Sharing
│   └── find_my_mac.py      # Find My Mac / Activation Lock
├── lib/                    # Core framework
│   ├── models.py           # CheckResult, AuditReport data models
│   ├── output.py           # Terminal formatting & JSON export
│   └── util.py             # Command execution helpers
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

## Disclaimer

This tool is provided as-is for security assessment purposes. It performs **read-only** operations and does not modify any system settings. Results should be validated manually. Use at your own risk.

## License

MIT
