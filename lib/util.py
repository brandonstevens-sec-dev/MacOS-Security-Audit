"""Utility helpers for running macOS system commands."""

import os
import subprocess
from typing import Optional


def is_admin() -> bool:
    """Return True if the current process is running with root/admin privileges."""
    return os.geteuid() == 0


def run_cmd(cmd: list[str], timeout: int = 10) -> tuple[Optional[str], Optional[str]]:
    """Run a command and return (stdout, stderr). Returns (None, error_msg) on failure."""
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        return result.stdout.strip(), result.stderr.strip()
    except FileNotFoundError:
        return None, f"Command not found: {cmd[0]}"
    except subprocess.TimeoutExpired:
        return None, f"Command timed out: {' '.join(cmd)}"
    except PermissionError:
        return None, f"Permission denied: {' '.join(cmd)}"


def read_plist_key(domain: str, key: str) -> tuple[Optional[str], Optional[str]]:
    """Read a single key from a plist domain using `defaults read`."""
    return run_cmd(["defaults", "read", domain, key])
