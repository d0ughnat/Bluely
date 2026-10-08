from __future__ import annotations

import hashlib
import mimetypes
import os
import shutil
import stat
import subprocess
import sys
import tempfile
from pathlib import Path

from .config import DATA_DIR, Settings

RULES_DIR = Path(__file__).parent / "rules"


def allowed_download(path: str, settings: Settings) -> Path:
    candidate = Path(path).expanduser()
    root = Path(settings.downloads_dir).expanduser().resolve()
    home = Path.home().resolve()
    if candidate.is_symlink() or not candidate.is_file():
        raise ValueError("Download must be a regular file")
    resolved = candidate.resolve()
    if root not in resolved.parents and home not in resolved.parents:
        raise ValueError("File is outside the user's home and Downloads folders")
    return resolved


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def scan_file(path: str, settings: Settings) -> dict:
    source = allowed_download(path, settings)
    source_stat = source.stat()
    if source_stat.st_size > settings.max_scan_bytes:
        return {"status": "skipped_size", "path": str(source), "size": source_stat.st_size,
                "sha256": "", "evidence": []}
    scan_root = DATA_DIR / "scan" if sys.platform == "win32" else DATA_DIR
    scan_root.mkdir(mode=0o700, parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="scan-", dir=scan_root) as temp_dir:
        snapshot = Path(temp_dir) / ("sample.bin" if sys.platform == "win32" else "sample")
        descriptor = os.open(source, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        digest = hashlib.sha256()
        try:
            before = os.fstat(descriptor)
            if not stat.S_ISREG(before.st_mode) or before.st_size > settings.max_scan_bytes:
                raise ValueError("Download is not a scannable regular file")
            with os.fdopen(descriptor, "rb", closefd=False) as input_file, snapshot.open("wb") as output:
                while chunk := input_file.read(1024 * 1024):
                    digest.update(chunk)
                    output.write(chunk)
            after = os.fstat(descriptor)
            if (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns) != \
                    (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns):
                raise ValueError("Download changed during scan")
        finally:
            os.close(descriptor)
        evidence: list[dict] = []
        tools: dict[str, str] = {}
        mime = mimetypes.guess_type(source.name)[0] or "application/octet-stream"
        if shutil.which("file"):
            result = subprocess.run(["file", "--brief", "--mime-type", str(snapshot)],
                                    capture_output=True, text=True, timeout=10, check=False)
            if result.returncode == 0:
                mime = result.stdout.strip()[:100]
        if sys.platform == "win32":
            from .windows_pipe import SCANNER_PIPE, request as pipe_request
            try:
                verdict = pipe_request(SCANNER_PIPE, {"method": "scan", "path": str(snapshot),
                                                        "sha256": digest.hexdigest()}, 180000)
                if verdict.get("status") == "detected":
                    evidence.append({"source": "defender", "code": "defender_detected",
                                     "detail": "Microsoft Defender detected a threat in the scan snapshot"})
                tools["defender"] = verdict.get("status", "error")
            except (OSError, ValueError):
                tools["defender"] = "unavailable"
        elif shutil.which("clamscan"):
            try:
                result = subprocess.run(["clamscan", "--no-summary", str(snapshot)],
                                        capture_output=True, text=True, timeout=120, check=False)
                if result.returncode == 1:
                    evidence.append({"source": "clamav", "code": "clamav_detected",
                                     "detail": result.stdout.strip()[:300]})
                    tools["clamav"] = "detected"
                else:
                    tools["clamav"] = "clean" if result.returncode == 0 else "error"
            except subprocess.TimeoutExpired:
                tools["clamav"] = "timeout"
        else:
            tools["clamav"] = "missing"
        if shutil.which("yara"):
            try:
                result = subprocess.run(["yara", "-r", str(RULES_DIR / "blueguard.yar"), str(snapshot)],
                                        capture_output=True, text=True, timeout=30, check=False)
                if result.returncode == 0:
                    for line in result.stdout.splitlines()[:20]:
                        rule = line.split(" ", 1)[0]
                        if rule:
                            code = "yara_high_confidence" if rule.startswith("HighConfidence_") else "yara_match"
                            evidence.append({"source": "yara", "code": code, "detail": rule[:100]})
                    tools["yara"] = "matched" if result.stdout.strip() else "clean"
                else:
                    tools["yara"] = "error"
            except subprocess.TimeoutExpired:
                tools["yara"] = "timeout"
        else:
            tools["yara"] = "missing"
        return {"status": "scanned" if any(value in {"clean", "detected", "matched"}
                                             for value in tools.values()) else "unscanned",
                "path": str(source), "size": before.st_size, "sha256": digest.hexdigest(),
                "mime": mime, "tools": tools, "evidence": evidence}
