from __future__ import annotations

import hashlib
import base64
import ipaddress
import json
import os
import re
import stat
import threading
import time
import uuid
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.parse import quote, urlencode, urlsplit
from urllib.request import Request, urlopen

from . import secrets

BASE_URL = "https://www.virustotal.com/api/v3"
PRIVATE_SUFFIXES = (".local", ".localhost", ".localdomain", ".internal", ".test",
                    ".invalid", ".lan", ".home", ".example", ".corp", ".intranet",
                    ".onion", ".arpa")
MAX_UPLOAD_BYTES = 32 * 1024 * 1024


def public_domain(url: str) -> str:
    parsed = urlsplit(url.strip())
    if parsed.scheme.lower() not in {"http", "https"} or not parsed.hostname:
        raise ValueError("Enter an HTTP or HTTPS website")
    if parsed.username or parsed.password:
        raise ValueError("Do not include credentials in the website address")
    host = parsed.hostname.rstrip(".").encode("idna").decode("ascii").lower()
    if len(host) > 253 or "." not in host or host.endswith(PRIVATE_SUFFIXES):
        raise ValueError("Private or local domains cannot be sent to VirusTotal")
    try:
        ipaddress.ip_address(host)
    except ValueError:
        pass
    else:
        raise ValueError("IP addresses cannot be sent to VirusTotal")
    if any(not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", label)
           for label in host.split(".")):
        raise ValueError("Invalid domain")
    return host


def public_url(url: str) -> tuple[str, str]:
    value = url.strip()
    if len(value) > 4096:
        raise ValueError("URL is too long")
    host = public_domain(value)
    parsed = urlsplit(value)
    if parsed.fragment:
        raise ValueError("Remove the URL fragment before checking")
    return value, host


def public_ip(value: str) -> str:
    try:
        address = ipaddress.ip_address(value.strip())
    except ValueError as error:
        raise ValueError("Enter a valid public IP address") from error
    if not address.is_global:
        raise ValueError("Private or local IP addresses cannot be sent to VirusTotal")
    return str(address)


class VirusTotal:
    def __init__(self):
        self._lock = threading.Lock()
        self._requests: list[float] = []
        self._cache: dict[tuple[str, str, str], tuple[float, dict]] = {}

    def lookup_file(self, sha256: str) -> dict:
        if not re.fullmatch(r"[0-9a-fA-F]{64}", sha256):
            raise ValueError("A SHA-256 hash is required")
        return self._lookup("files", sha256.lower())

    def lookup_domain(self, url: str) -> dict:
        value = url if url.lower().startswith(("http://", "https://")) else "https://" + url
        return self._lookup("domains", public_domain(value))

    def lookup_ip(self, address: str) -> dict:
        return self._lookup("ip_addresses", public_ip(address))

    def lookup_url(self, url: str, confirmed: bool = False) -> dict:
        if not confirmed:
            raise ValueError("Confirm sending the full URL to VirusTotal")
        value, host = public_url(url)
        identifier = base64.urlsafe_b64encode(value.encode()).decode().rstrip("=")
        return self._lookup("urls", identifier, display_id=host)

    def submit_url(self, url: str, confirmed: bool = False) -> dict:
        if not confirmed:
            raise ValueError("Confirm submitting the full URL to VirusTotal")
        value, host = public_url(url)
        body = urlencode({"url": value}).encode()
        return self._submit("urls", body, "application/x-www-form-urlencoded", host)

    def upload_file(self, path: str, confirmed: bool = False) -> dict:
        if not confirmed:
            raise ValueError("Confirm uploading the file to VirusTotal")
        if Path(path).is_symlink():
            raise ValueError("Symbolic links cannot be uploaded")
        flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
        fd = os.open(path, flags)
        try:
            before = os.fstat(fd)
            if not stat.S_ISREG(before.st_mode):
                raise ValueError("Select a regular file")
            if before.st_size > MAX_UPLOAD_BYTES:
                raise ValueError("VirusTotal uploads are limited to 32 MB in Bluely")
            with os.fdopen(fd, "rb", closefd=False) as stream:
                content = stream.read(MAX_UPLOAD_BYTES + 1)
            after = os.fstat(fd)
            if len(content) > MAX_UPLOAD_BYTES or (before.st_size, before.st_mtime_ns) != (after.st_size, after.st_mtime_ns):
                raise ValueError("File changed during upload preparation")
        finally:
            os.close(fd)
        digest = hashlib.sha256(content).hexdigest()
        boundary = "bluely-" + uuid.uuid4().hex
        body = (f"--{boundary}\r\nContent-Disposition: form-data; name=\"file\"; filename=\"sample.bin\"\r\n"
                "Content-Type: application/octet-stream\r\n\r\n").encode() + content + f"\r\n--{boundary}--\r\n".encode()
        result = self._submit("files", body, f"multipart/form-data; boundary={boundary}", digest)
        result["sha256"] = digest
        return result

    def analysis(self, analysis_id: str) -> dict:
        if not re.fullmatch(r"[A-Za-z0-9_-]{8,200}", analysis_id):
            raise ValueError("Invalid analysis ID")
        key = secrets.get("virustotal_api_key")
        if not key:
            return {"status": "unconfigured"}
        if not self._reserve():
            return {"status": "rate_limited"}
        try:
            data = self._request("GET", f"analyses/{quote(analysis_id, safe='')}", key)
            attributes = data["data"]["attributes"]
            status = attributes.get("status", "unknown")
            stats = attributes.get("stats", {}) if status == "completed" else {}
            return {"status": status, "analysis_id": analysis_id,
                    **{name: max(0, int(stats.get(name, 0))) for name in
                       ("malicious", "suspicious", "harmless", "undetected")}}
        except HTTPError as error:
            return {"status": "not_found" if error.code == 404 else "rate_limited" if error.code == 429 else "unavailable"}
        except (URLError, TimeoutError, ValueError, KeyError, TypeError):
            return {"status": "unavailable"}

    def _reserve(self) -> bool:
        now = time.monotonic()
        with self._lock:
            self._requests = [value for value in self._requests if now - value < 60]
            if len(self._requests) >= 4:
                return False
            self._requests.append(now)
        return True

    def _request(self, method: str, endpoint: str, key: str, body: bytes | None = None,
                 content_type: str | None = None) -> dict:
        headers = {"Accept": "application/json", "x-apikey": key}
        if content_type:
            headers["Content-Type"] = content_type
        request = Request(f"{BASE_URL}/{endpoint}", data=body, headers=headers, method=method)
        with urlopen(request, timeout=12) as response:
            raw = response.read(3 * 1024 * 1024 + 1)
            if len(raw) > 3 * 1024 * 1024:
                raise ValueError("VirusTotal response is too large")
            return json.loads(raw)

    def _submit(self, kind: str, body: bytes, content_type: str, display_id: str) -> dict:
        key = secrets.get("virustotal_api_key")
        if not key:
            return {"status": "unconfigured", "kind": kind, "id": display_id}
        if not self._reserve():
            return {"status": "rate_limited", "kind": kind, "id": display_id}
        try:
            data = self._request("POST", kind, key, body, content_type)
            analysis_id = str(data["data"]["id"])
            if not re.fullmatch(r"[A-Za-z0-9_-]{8,200}", analysis_id):
                raise ValueError("Invalid analysis ID")
            return {"status": "queued", "kind": kind, "id": display_id, "analysis_id": analysis_id}
        except HTTPError as error:
            status = "rate_limited" if error.code == 429 else "unavailable"
        except (URLError, TimeoutError, ValueError, KeyError, TypeError):
            status = "unavailable"
        return {"status": status, "kind": kind, "id": display_id}

    def _lookup(self, kind: str, identifier: str, display_id: str | None = None) -> dict:
        display_id = display_id or identifier
        key = secrets.get("virustotal_api_key")
        if not key:
            return {"status": "unconfigured", "kind": kind, "id": display_id}
        key_id = hashlib.sha256(key.encode()).hexdigest()[:16]
        cache_key = (key_id, kind, identifier)
        now = time.monotonic()
        with self._lock:
            cached = self._cache.get(cache_key)
            if cached and cached[0] > now:
                return cached[1].copy()
        if not self._reserve():
            return {"status": "rate_limited", "kind": kind, "id": display_id}

        try:
            attributes = self._request("GET", f"{kind}/{quote(identifier, safe='')}", key)["data"]["attributes"]
            stats = attributes.get("last_analysis_stats", {})
            malicious = max(0, int(stats.get("malicious", 0)))
            suspicious = max(0, int(stats.get("suspicious", 0)))
            harmless = max(0, int(stats.get("harmless", 0)))
            undetected = max(0, int(stats.get("undetected", 0)))
            status = ("no_data" if malicious + suspicious + harmless + undetected == 0 else
                      "malicious" if malicious >= 5 else "suspicious"
                      if malicious >= 2 or suspicious >= 3 else "low_signal"
                      if malicious or suspicious else "no_match")
            result = {"status": status, "kind": kind, "id": display_id,
                      "malicious": malicious, "suspicious": suspicious,
                      "harmless": harmless, "undetected": undetected,
                      "last_analysis_date": attributes.get("last_analysis_date")}
            ttl = 900
        except HTTPError as error:
            result = {"status": "not_found" if error.code == 404 else
                      "rate_limited" if error.code == 429 else "unavailable",
                      "kind": kind, "id": display_id}
            ttl = 60
        except (URLError, TimeoutError, ValueError, KeyError, TypeError, json.JSONDecodeError):
            result = {"status": "unavailable", "kind": kind, "id": display_id}
            ttl = 60
        with self._lock:
            self._cache[cache_key] = (time.monotonic() + ttl, result)
        return result.copy()
