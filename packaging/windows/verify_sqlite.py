"""Verify SQLite in CPython and in the actual PyInstaller Windows output."""

from __future__ import annotations

import argparse
import subprocess
from pathlib import Path


def verify_source() -> None:
    import _sqlite3
    import sqlite3

    if not Path(_sqlite3.__file__).is_file():
        raise RuntimeError("Python installation has no _sqlite3 native extension")
    with sqlite3.connect(":memory:") as database:
        database.execute("CREATE TABLE test (value TEXT)")
        database.execute("INSERT INTO test VALUES (?)", ("source-ok",))
        if database.execute("SELECT value FROM test").fetchone()[0] != "source-ok":
            raise RuntimeError("Python SQLite readback failed")


def verify_onedir(folder: Path, executable_name: str) -> None:
    if not folder.is_dir():
        raise RuntimeError(f"Missing PyInstaller folder: {folder}")
    if not list(folder.rglob("_sqlite3*.pyd")):
        raise RuntimeError(f"Missing _sqlite3.pyd in {folder}")
    if not list(folder.rglob("sqlite3.dll")):
        raise RuntimeError(f"Missing sqlite3.dll in {folder}")
    executable = folder / executable_name
    if not executable.is_file():
        raise RuntimeError(f"Missing packaged executable: {executable}")


def run_self_test(executable: Path) -> None:
    result = subprocess.run([str(executable.resolve()), "--self-test"],
                            timeout=60, check=False)
    if result.returncode:
        raise RuntimeError(f"Frozen SQLite self-test failed ({result.returncode}): {executable}")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--source", action="store_true")
    parser.add_argument("--agent-folder", type=Path)
    parser.add_argument("--native-host-folder", type=Path)
    parser.add_argument("--onefile", type=Path)
    args = parser.parse_args()
    if args.source:
        verify_source()
        print("Source Python SQLite passed")
    if args.agent_folder:
        verify_onedir(args.agent_folder, "bluely-agent.exe")
        run_self_test(args.agent_folder / "bluely-agent.exe")
        print("Packaged onedir agent SQLite passed")
    if args.native_host_folder:
        verify_onedir(args.native_host_folder, "bluely-native-host.exe")
        print("Packaged onedir native host SQLite libraries are present")
    if args.onefile:
        run_self_test(args.onefile)
        print("Packaged onefile agent SQLite passed")


if __name__ == "__main__":
    main()
