"""Utility helpers for running macOS system commands."""

import os
import subprocess
from dataclasses import dataclass
from typing import Optional


def is_admin() -> bool:
    """Return True if the current process is running with root/admin privileges."""
    return os.geteuid() == 0


@dataclass
class CmdResult:
    """Structured result from a subprocess call."""
    stdout: str
    stderr: str
    returncode: int

    @property
    def success(self) -> bool:
        return self.returncode == 0


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


def run_cmd_full(cmd: list[str], timeout: int = 10) -> CmdResult:
    """Run a command and return full structured result including return code."""
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        return CmdResult(
            stdout=result.stdout.strip(),
            stderr=result.stderr.strip(),
            returncode=result.returncode,
        )
    except FileNotFoundError:
        return CmdResult(stdout="", stderr=f"Command not found: {cmd[0]}", returncode=-1)
    except subprocess.TimeoutExpired:
        return CmdResult(stdout="", stderr=f"Command timed out: {' '.join(cmd)}", returncode=-1)
    except PermissionError:
        return CmdResult(stdout="", stderr=f"Permission denied: {' '.join(cmd)}", returncode=-1)


@dataclass
class PlistValue:
    """Result of reading a plist key."""
    value: Optional[str]  # The value string, or None if not found / error
    exists: bool           # Whether the key exists in the plist
    error: Optional[str]   # Error message if the read failed

    @property
    def as_bool(self) -> Optional[bool]:
        """Interpret the value as a boolean (handles 1/0/true/false/yes/no)."""
        if self.value is None:
            return None
        v = self.value.strip().lower()
        if v in ("1", "true", "yes"):
            return True
        if v in ("0", "false", "no"):
            return False
        return None


def read_plist_key(domain: str, key: str) -> tuple[Optional[str], Optional[str]]:
    """Read a single key from a plist domain using `defaults read`.

    Legacy interface — returns (stdout, stderr) for backward compatibility.
    """
    return run_cmd(["defaults", "read", domain, key])


def read_plist_key_full(domain: str, key: str) -> PlistValue:
    """Read a single key from a plist domain with structured result.

    Distinguishes between:
      - Key exists with a value
      - Key does not exist in the plist
      - Read error (permissions, command not found, etc.)
    """
    result = run_cmd_full(["defaults", "read", domain, key])

    if result.returncode == -1:
        # Command-level failure (not found, timeout, permission)
        return PlistValue(value=None, exists=False, error=result.stderr)

    if result.returncode != 0:
        if "does not exist" in result.stderr:
            return PlistValue(value=None, exists=False, error=None)
        return PlistValue(value=None, exists=False, error=result.stderr)

    return PlistValue(value=result.stdout, exists=True, error=None)
