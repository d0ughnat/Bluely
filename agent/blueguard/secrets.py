from __future__ import annotations

import keyring

SERVICE = "blueguard"
NAMES = {"gmail_client_secret", "gmail_refresh_token", "safe_browsing_api_key",
         "virustotal_api_key", "huggingface_api_key", "openai_api_key", "anthropic_api_key"}


def get(name: str) -> str:
    if name not in NAMES:
        raise ValueError("Unknown secret")
    try:
        return keyring.get_password(SERVICE, name) or ""
    except keyring.errors.KeyringError:
        return ""


def set_secret(name: str, value: str) -> None:
    if name not in NAMES:
        raise ValueError("Unknown secret")
    if value:
        keyring.set_password(SERVICE, name, value)
    else:
        try:
            keyring.delete_password(SERVICE, name)
        except keyring.errors.PasswordDeleteError:
            pass


def availability() -> dict[str, bool]:
    return {name: bool(get(name)) for name in NAMES}
