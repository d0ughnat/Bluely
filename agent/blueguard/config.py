from __future__ import annotations

import json
import os
import sys
from dataclasses import asdict, dataclass, fields
from pathlib import Path


def _xdg(name: str, fallback: str) -> Path:
    return Path(os.environ.get(name, str(Path.home() / fallback))) / "blueguard"


if sys.platform == "win32":
    DATA_DIR = Path(os.environ.get("LOCALAPPDATA", str(Path.home() / "AppData/Local"))) / "Bluely"
    CONFIG_DIR = DATA_DIR
    RUNTIME_DIR = DATA_DIR
    SOCKET_PATH = DATA_DIR / "blueguard.sock"  # Unix-only; Windows uses a named pipe.
else:
    DATA_DIR = _xdg("XDG_DATA_HOME", ".local/share")
    CONFIG_DIR = _xdg("XDG_CONFIG_HOME", ".config")
    RUNTIME_DIR = Path(os.environ.get("XDG_RUNTIME_DIR", str(DATA_DIR)))
    SOCKET_PATH = RUNTIME_DIR / "blueguard.sock"


def default_downloads_dir() -> str:
    if sys.platform == "win32":
        try:
            import winreg
            with winreg.OpenKey(winreg.HKEY_CURRENT_USER,
                                r"Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders") as key:
                value, _ = winreg.QueryValueEx(key, "{374DE290-123F-4565-9164-39C4925E467B}")
                return os.path.expandvars(value)
        except (OSError, ValueError):
            pass
    return str(Path.home() / "Downloads")


@dataclass
class Settings:
    model_provider: str = "ollama"
    model_name: str = "qwen3:8b"
    model_endpoint: str = "http://127.0.0.1:11434"
    gmail_client_id: str = ""
    downloads_dir: str = default_downloads_dir()
    email_interval_minutes: int = 15
    max_scan_bytes: int = 512 * 1024 * 1024
    max_message_bytes: int = 1024 * 1024
    virustotal_file_lookups: bool = False

    @classmethod
    def load(cls) -> "Settings":
        path = CONFIG_DIR / "settings.json"
        if not path.exists():
            return cls()
        data = json.loads(path.read_text(encoding="utf-8"))
        allowed = {field.name for field in fields(cls)}
        return cls(**{key: value for key, value in data.items() if key in allowed})

    def save(self) -> None:
        CONFIG_DIR.mkdir(mode=0o700, parents=True, exist_ok=True)
        path = CONFIG_DIR / "settings.json"
        tmp = path.with_suffix(".tmp")
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(asdict(self), handle, indent=2)
        os.replace(tmp, path)
        path.chmod(0o600)

    def update(self, changes: dict) -> None:
        allowed = {field.name for field in fields(self)}
        candidate = asdict(self)
        for key, value in changes.items():
            if key not in allowed:
                raise ValueError(f"Unknown setting: {key}")
            candidate[key] = value
        if candidate["model_provider"] not in {"ollama", "llama_cpp", "huggingface", "openai", "anthropic", "codex"}:
            raise ValueError("Unsupported model provider")
        if not 1 <= candidate["email_interval_minutes"] <= 1440:
            raise ValueError("Email interval must be 1-1440 minutes")
        if not 1024 <= candidate["max_scan_bytes"] <= 2 * 1024 * 1024 * 1024:
            raise ValueError("Invalid maximum scan size")
        if type(candidate["virustotal_file_lookups"]) is not bool:
            raise ValueError("VirusTotal file lookups must be enabled or disabled")
        for key, value in candidate.items():
            setattr(self, key, value)
