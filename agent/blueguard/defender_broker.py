"""Small privileged Windows scan broker. It performs no file modifications."""

from __future__ import annotations

import hashlib
import os
import re
import subprocess
import threading
from pathlib import Path

from .windows_pipe import SCANNER_PIPE, serve

_SCAN_LOCK = threading.Lock()


def defender_executable() -> Path | None:
    program_data = Path(os.environ.get("ProgramData", r"C:\ProgramData"))
    platform = program_data / "Microsoft/Windows Defender/Platform"
    if platform.is_dir():
        for folder in sorted(platform.iterdir(), reverse=True):
            candidate = folder / "MpCmdRun.exe"
            if candidate.is_file():
                return candidate
    fallback = Path(os.environ.get("ProgramFiles", r"C:\Program Files")) / "Windows Defender/MpCmdRun.exe"
    return fallback if fallback.is_file() else None


def _caller_scan_root(handle) -> Path:
    import win32api
    import win32con
    import win32pipe
    import win32profile
    import win32security

    win32pipe.ImpersonateNamedPipeClient(handle)
    try:
        token = win32security.OpenThreadToken(
            win32api.GetCurrentThread(), win32con.TOKEN_QUERY | win32con.TOKEN_DUPLICATE, True)
        environment = win32profile.CreateEnvironmentBlock(token, False)
        local = next((value for key, value in environment.items()
                      if key.upper() == "LOCALAPPDATA"), None)
        home = Path(win32profile.GetUserProfileDirectory(token)).resolve()
        return Path(local).resolve() / "Bluely/scan" if local else home / "AppData/Local/Bluely/scan"
    finally:
        win32security.RevertToSelf()


def _validated_snapshot(raw: str, scan_root: Path) -> Path:
    candidate = Path(raw)
    if not candidate.is_absolute() or candidate.is_symlink() or not candidate.is_file():
        raise ValueError("Invalid scan snapshot")
    expected = scan_root
    if any(part.is_symlink() for part in (expected, expected.parent, candidate.parent)):
        raise ValueError("Scan snapshot path contains a link")
    resolved = candidate.resolve()
    if expected.resolve() not in resolved.parents or resolved.suffix != ".bin":
        raise ValueError("Scan snapshot is outside the caller's Bluely scan folder")
    return resolved


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def scan(snapshot: Path, expected_hash: str) -> dict:
    if not re.fullmatch(r"[a-f0-9]{64}", expected_hash) or _sha256(snapshot) != expected_hash:
        raise ValueError("Scan snapshot changed")
    executable = defender_executable()
    if executable is None:
        return {"status": "unavailable"}
    try:
        with _SCAN_LOCK:
            result = subprocess.run([str(executable), "-Scan", "-ScanType", "3", "-File",
                                     str(snapshot), "-DisableRemediation"], capture_output=True,
                                    text=True, timeout=180, check=False)
    except (OSError, subprocess.TimeoutExpired):
        return {"status": "error"}
    if not snapshot.is_file() or _sha256(snapshot) != expected_hash:
        return {"status": "changed"}
    output = (result.stdout + "\n" + result.stderr).lower()
    detected = re.search(r"\b(?:found [1-9]\d* threats?|(?<!no )threats? found|"
                         r"(?<!no )malware (?:found|detected))\b", output)
    if result.returncode in (0, 2) and detected:
        return {"status": "detected"}
    if result.returncode == 0:
        return {"status": "clean"}
    return {"status": "error"}


def handle(payload: dict, pipe_handle: object) -> dict:
    method = payload.get("method")
    if method == "status":
        return {"ready": defender_executable() is not None}
    if method != "scan":
        raise ValueError("Unknown scanner request")
    scan_root = _caller_scan_root(pipe_handle)
    snapshot = _validated_snapshot(str(payload.get("path", "")), scan_root)
    result = scan(snapshot, str(payload.get("sha256", "")))
    return result


def main() -> None:
    if os.name != "nt":
        raise SystemExit("Defender broker is available only on Windows")
    serve(SCANNER_PIPE, handle, user_only=False)


if __name__ == "__main__":
    main()
