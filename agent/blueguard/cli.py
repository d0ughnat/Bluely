from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
from pathlib import Path

from .config import DATA_DIR
from .native_host import main as native_main
from .service import request, serve


def _say(message: str) -> None:
    if sys.stdout is not None:
        print(message)


def setup(extension_id: str) -> None:
    if extension_id and not re.fullmatch(r"[a-p]{32}", extension_id):
        raise ValueError("Chromium extension ID must be 32 letters from a to p")
    if sys.platform == "win32":
        setup_windows(extension_id)
        return
    unit_dir = Path.home() / ".config/systemd/user"
    unit_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
    executable = Path(sys.executable).absolute()
    unit = unit_dir / "blueguard-agent.service"
    unit.write_text("[Unit]\nDescription=Bluely local security agent\n"
                    "After=default.target\n\n[Service]\n"
                    f"ExecStart={executable} -m blueguard service\n"
                    "Restart=on-failure\nRestartSec=5\n\n[Install]\n"
                    "WantedBy=default.target\n", encoding="utf-8")
    subprocess.run(["systemctl", "--user", "daemon-reload"], check=True)
    subprocess.run(["systemctl", "--user", "enable", "--now", "blueguard-agent.service"], check=True)
    print(f"User service installed: {unit}")
    if extension_id:
        DATA_DIR.mkdir(mode=0o700, parents=True, exist_ok=True)
        launcher = DATA_DIR / "native-host"
        launcher.write_text(f"#!{executable}\nfrom blueguard.native_host import main\nmain()\n",
                            encoding="utf-8")
        launcher.chmod(0o700)
        for browser in ("google-chrome", "chromium"):
            host_dir = Path.home() / f".config/{browser}/NativeMessagingHosts"
            host_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
            manifest = host_dir / "com.blueguard.agent.json"
            manifest.write_text(json.dumps({"name": "com.blueguard.agent",
                                            "description": "Bluely local security agent",
                                            "path": str(launcher), "type": "stdio",
                                            "allowed_origins": [f"chrome-extension://{extension_id}/"]}, indent=2),
                                encoding="utf-8")
            manifest.chmod(0o600)
            print(f"Chromium native host installed: {manifest}")


def setup_windows(extension_id: str) -> None:
    import winreg

    if extension_id and not re.fullmatch(r"[a-p]{32}", extension_id):
        raise ValueError("Chromium extension ID must be 32 letters from a to p")

    executable = Path(sys.executable).resolve()
    agent_command = f'"{executable}" service' if getattr(sys, "frozen", False) else \
        f'"{executable}" -m blueguard service'
    with winreg.CreateKey(winreg.HKEY_CURRENT_USER,
                          r"Software\Microsoft\Windows\CurrentVersion\Run") as key:
        winreg.SetValueEx(key, "BluelyAgent", 0, winreg.REG_SZ, agent_command)
    _say("Bluely agent registered to start at sign-in")
    if extension_id:
        DATA_DIR.mkdir(mode=0o700, parents=True, exist_ok=True)
        host = executable.with_name("bluely-native-host.exe")
        if not host.exists():
            raise FileNotFoundError("Bluely native messaging host is not installed")
        manifest = DATA_DIR / "native-host.json"
        manifest.write_text(json.dumps({"name": "com.blueguard.agent",
                                        "description": "Bluely local security agent",
                                        "path": str(host), "type": "stdio",
                                        "allowed_origins": [f"chrome-extension://{extension_id}/"]}, indent=2),
                            encoding="utf-8")
        for browser in (r"Software\Google\Chrome\NativeMessagingHosts",
                        r"Software\Chromium\NativeMessagingHosts",
                        r"Software\Microsoft\Edge\NativeMessagingHosts"):
            with winreg.CreateKey(winreg.HKEY_CURRENT_USER,
                                  browser + r"\com.blueguard.agent") as key:
                winreg.SetValueEx(key, "", 0, winreg.REG_SZ, str(manifest))
        _say(f"Chrome and Edge native messaging registered: {manifest}")
    try:
        request("status", timeout=1)
    except (OSError, ValueError):
        flags = subprocess.CREATE_NO_WINDOW | subprocess.DETACHED_PROCESS
        command = [str(executable), "service"] if getattr(sys, "frozen", False) else \
            [str(executable), "-m", "blueguard", "service"]
        subprocess.Popen(command, creationflags=flags, close_fds=True)


def main() -> None:
    parser = argparse.ArgumentParser(prog="bluely")
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("service")
    sub.add_parser("native-host")
    setup_parser = sub.add_parser("setup")
    setup_parser.add_argument("--extension-id", default="")
    rpc_parser = sub.add_parser("rpc")
    rpc_parser.add_argument("method")
    rpc_parser.add_argument("params", nargs="?", default="{}")
    args = parser.parse_args()
    if args.command == "service":
        serve()
    elif args.command == "native-host":
        native_main()
    elif args.command == "setup":
        setup(args.extension_id)
    elif args.command == "rpc":
        _say(json.dumps(request(args.method, json.loads(args.params)), indent=2))
