"""Windows-only newline-delimited JSON RPC over local named pipes."""

from __future__ import annotations

import json
import threading
from collections.abc import Callable

AGENT_PIPE = r"\\.\pipe\BluelyAgent"
SCANNER_PIPE = r"\\.\pipe\BluelyScanner"
MAX_MESSAGE = 1024 * 1024


def current_user_sid() -> str:
    import win32api
    import win32con
    import win32security

    token = win32security.OpenProcessToken(win32api.GetCurrentProcess(), win32con.TOKEN_QUERY)
    sid = win32security.GetTokenInformation(token, win32security.TokenUser)[0]
    return win32security.ConvertSidToStringSid(sid)


def _attributes(sddl: str):
    import pywintypes
    import win32security

    attributes = pywintypes.SECURITY_ATTRIBUTES()
    attributes.SECURITY_DESCRIPTOR = win32security.ConvertStringSecurityDescriptorToSecurityDescriptor(
        sddl, win32security.SDDL_REVISION_1)
    return attributes


def request(name: str, payload: dict, timeout_ms: int = 20000) -> dict:
    import pywintypes
    import win32con
    import win32file
    import win32pipe

    encoded = (json.dumps(payload) + "\n").encode("utf-8")
    if len(encoded) > MAX_MESSAGE:
        raise ValueError("Request is too large")
    try:
        win32pipe.WaitNamedPipe(name, timeout_ms)
        access = (0x120003 if name == SCANNER_PIPE else
                  win32con.GENERIC_READ | win32con.GENERIC_WRITE)
        handle = win32file.CreateFile(name, access,
                                      0, None, win32con.OPEN_EXISTING, 0, None)
        try:
            win32file.WriteFile(handle, encoded)
            chunks = bytearray()
            while len(chunks) <= MAX_MESSAGE:
                _, part = win32file.ReadFile(handle, min(65536, MAX_MESSAGE + 1 - len(chunks)))
                if not part:
                    break
                chunks.extend(part)
                if chunks.endswith(b"\n"):
                    return json.loads(chunks)
            raise ValueError("Agent response was incomplete or too large")
        finally:
            handle.Close()
    except pywintypes.error as error:
        raise OSError(str(error)) from error


def serve(name: str, handler: Callable[[dict, object], dict], *, user_only: bool) -> None:
    import pywintypes
    import win32file
    import win32pipe

    sid = current_user_sid() if user_only else None
    # Scanner clients may read and write data, but cannot create a new pipe instance.
    sddl = (f"D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GA;;;{sid})" if sid else
            "D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;0x120003;;;AU)")
    attributes = _attributes(sddl)
    slots = threading.Semaphore(16)

    def serve_connection(handle) -> None:
        try:
            chunks = bytearray()
            while len(chunks) <= MAX_MESSAGE:
                _, part = win32file.ReadFile(handle, min(65536, MAX_MESSAGE + 1 - len(chunks)))
                if not part:
                    return
                chunks.extend(part)
                if chunks.endswith(b"\n"):
                    break
            if len(chunks) > MAX_MESSAGE:
                return
            try:
                reply = handler(json.loads(chunks), handle)
            except Exception as error:
                reply = {"ok": False, "error": str(error)[:300]}
            encoded = (json.dumps(reply) + "\n").encode("utf-8")
            if len(encoded) <= MAX_MESSAGE:
                win32file.WriteFile(handle, encoded)
        except (OSError, ValueError, pywintypes.error):
            pass
        finally:
            try:
                win32pipe.DisconnectNamedPipe(handle)
            except pywintypes.error:
                pass
            handle.Close()
            slots.release()

    while True:
        slots.acquire()
        handle = win32pipe.CreateNamedPipe(
            name, win32pipe.PIPE_ACCESS_DUPLEX,
            win32pipe.PIPE_TYPE_BYTE | win32pipe.PIPE_READMODE_BYTE |
            win32pipe.PIPE_WAIT | win32pipe.PIPE_REJECT_REMOTE_CLIENTS,
            16, MAX_MESSAGE, MAX_MESSAGE, 20000, attributes)
        try:
            win32pipe.ConnectNamedPipe(handle, None)
        except pywintypes.error as error:
            if error.winerror != 535:  # ERROR_PIPE_CONNECTED
                handle.Close()
                slots.release()
                raise
        threading.Thread(target=serve_connection, args=(handle,), daemon=True).start()
