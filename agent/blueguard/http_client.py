from __future__ import annotations

import json
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen


class RemoteError(RuntimeError):
    pass


def request_json(url: str, *, method: str = "GET", body: dict | None = None,
                 headers: dict[str, str] | None = None, timeout: int = 20) -> dict:
    data = json.dumps(body).encode() if body is not None else None
    request = Request(url, data=data, method=method,
                      headers={"Accept": "application/json",
                               **({"Content-Type": "application/json"} if data is not None else {}),
                               **(headers or {})})
    try:
        with urlopen(request, timeout=timeout) as response:
            return json.load(response)
    except HTTPError as error:
        # Remote bodies can contain private request details; keep them out of the UI and audit log.
        raise RemoteError(f"Remote service returned HTTP {error.code}") from error
    except (URLError, TimeoutError, ValueError) as error:
        raise RemoteError(f"Remote service unavailable: {type(error).__name__}") from error
