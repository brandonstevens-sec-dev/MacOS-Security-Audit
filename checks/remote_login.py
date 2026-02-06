"""
Check: Remote Login (SSH)
==========================
Remote Login enables the SSH server (sshd) on macOS, allowing remote
shell access. While useful for administration, an enabled SSH server
increases the attack surface if not properly secured.

Why it matters:
  - Open SSH = remote attack surface for brute-force, credential stuffing
  - Should be disabled unless explicitly needed
  - If enabled, should use key-based auth and restrict allowed users

Commands used (read-only):
  - systemsetup -getremotelogin  (may require admin)
  - launchctl list com.openssh.sshd  (fallback)
"""

from lib.models import CheckResult, Severity, Status
from lib.util import run_cmd

# systemsetup -getremotelogin requires admin privileges on macOS.
REQUIRES_ADMIN = True


def check_remote_login() -> CheckResult:
    """Check whether Remote Login (SSH server) is enabled."""
    stdout, err = run_cmd(["systemsetup", "-getremotelogin"])
    output = stdout or err or ""

    if "remote login: off" in output.lower():
        return CheckResult(
            name="Remote Login (SSH)",
            status=Status.PASS,
            severity=Severity.HIGH,
            description="Check if the SSH server is disabled.",
            detail="Remote Login is OFF — SSH server is not running.",
            raw_output=output,
        )

    if "remote login: on" in output.lower():
        return CheckResult(
            name="Remote Login (SSH)",
            status=Status.WARN,
            severity=Severity.HIGH,
            description="Check if the SSH server is disabled.",
            detail="Remote Login is ON — SSH server is accepting connections.",
            recommendation="Disable if not needed: System Settings > General > Sharing > Remote Login, or run: sudo systemsetup -setremotelogin off",
            raw_output=output,
        )

    # Fallback: try launchctl
    stdout2, _ = run_cmd(["launchctl", "list", "com.openssh.sshd"])
    if stdout2 is not None and "com.openssh.sshd" in stdout2:
        return CheckResult(
            name="Remote Login (SSH)",
            status=Status.WARN,
            severity=Severity.HIGH,
            description="Check if the SSH server is disabled.",
            detail="SSH daemon appears to be loaded (launchctl fallback).",
            recommendation="Disable if not needed: System Settings > General > Sharing > Remote Login",
            raw_output=stdout2,
        )

    # Could not determine — may need admin
    if "requires admin" in output.lower() or "you need administrator" in output.lower():
        return CheckResult(
            name="Remote Login (SSH)",
            status=Status.WARN,
            severity=Severity.HIGH,
            description="Check if the SSH server is disabled.",
            detail="Could not determine SSH status — admin privileges may be required.",
            recommendation="Re-run with sudo for accurate results.",
        )

    return CheckResult(
        name="Remote Login (SSH)",
        status=Status.ERROR,
        severity=Severity.HIGH,
        description="Check if the SSH server is disabled.",
        detail=f"Could not determine Remote Login status: {output}",
        raw_output=output,
    )


def run_checks() -> list[CheckResult]:
    return [check_remote_login()]
