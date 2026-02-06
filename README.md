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

Some checks return more accurate results with admin privileges:

```bash
sudo python3 macos_audit.py
```

## Usage

```
python3 macos_audit.py [OPTIONS]

Options:
  --json FILE    Write results to a JSON file in addition to terminal output
  --help         Show help message
```

### Examples

Terminal-only output:
```bash
python3 macos_audit.py
```

Terminal output plus JSON report:
```bash
python3 macos_audit.py --json audit_report.json
```

## What Gets Checked

| Check | Command(s) | Severity | Why It Matters |
|-------|-----------|----------|----------------|
| **Firewall Enabled** | `socketfilterfw --getglobalstate` | High | Blocks unauthorized inbound connections |
| **Firewall Stealth Mode** | `socketfilterfw --getstealthmode` | Medium | Hides the machine from network probes |
| **Gatekeeper** | `spctl --status` | Critical | Prevents unsigned/tampered app execution |
| **FileVault Encryption** | `fdesetup status` | Critical | Protects data at rest on disk |
| **System Integrity Protection** | `csrutil status` | Critical | Protects system files from modification |
| **Auto Update Check** | `defaults read` SoftwareUpdate | High | Ensures update availability is known |
| **Auto Update Download** | `defaults read` SoftwareUpdate | Medium | Ensures updates are downloaded promptly |
| **Auto Install macOS Updates** | `defaults read` SoftwareUpdate | Medium | Ensures OS patches are applied |
| **Critical Security Updates** | `defaults read` SoftwareUpdate | High | Rapid Security Responses for active exploits |
| **Screen Lock Enabled** | `sysadminctl -screenLock` | High | Prevents unauthorized physical access |
| **Screen Lock Delay** | `defaults read` screensaver | Medium | Controls time-to-lock after idle |
| **Remote Login (SSH)** | `systemsetup -getremotelogin` | High | SSH server increases attack surface |
| **File Sharing (SMB)** | `launchctl list com.apple.smbd` | Medium | Exposes filesystem over the network |
| **Screen Sharing** | `launchctl list com.apple.screensharing` | Medium | Allows remote GUI control |
| **Find My Mac** | `defaults read` FindMyMac | Medium | Enables remote locate/lock/wipe |

## Output

### Terminal

The tool prints color-coded results:
- **Green `[PASS]`** — setting meets security best practice
- **Red `[FAIL]`** — setting does not meet security best practice
- **Yellow `[WARN]`** — setting is borderline or could not be fully verified
- **Gray `[ERR ]`** — check encountered an error (e.g., command not found)

A compliance summary is printed at the end with a pass/fail percentage.

### JSON

When `--json` is specified, a structured JSON file is written containing:
- System information
- Summary statistics (total, passed, failed, warnings, errors, compliance %)
- Full result details for each check

### Exit Code

- `0` — compliance percentage >= 80%
- `1` — compliance percentage < 80%

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
- Individual check functions returning `CheckResult` objects
- A `run_checks()` function that returns all results for that module

## Adding New Checks

1. Create a new file in `checks/` (e.g., `checks/bluetooth.py`)
2. Implement check functions returning `CheckResult` objects
3. Add a `run_checks()` function that returns a list of results
4. Register the module in `CHECK_MODULES` in `macos_audit.py`

## Disclaimer

This tool is provided as-is for security assessment purposes. It performs **read-only** operations and does not modify any system settings. Results should be validated manually. Use at your own risk.

## License

MIT
