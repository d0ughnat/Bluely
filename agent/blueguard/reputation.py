from __future__ import annotations

import base64
import binascii
import hashlib
import ipaddress
import re
import threading
import time
from urllib.parse import quote, unquote, urlencode, urlsplit

from .http_client import RemoteError, request_json
from .secrets import get


def _canonical_parts(url: str) -> tuple[str, str]:
    parsed = urlsplit(url.strip())
    if parsed.scheme.lower() not in {"http", "https"} or not parsed.hostname:
        raise ValueError("Only HTTP and HTTPS URLs can be checked")
    host = parsed.hostname.rstrip(".").lower().encode("idna").decode("ascii")
    try:
        host = str(ipaddress.ip_address(host))
    except ValueError:
        host = re.sub(r"\.+", ".", host)
    path = parsed.path or "/"
    # Safe Browsing canonicalization repeatedly unescapes before re-escaping unsafe bytes.
    for _ in range(10):
        decoded = unquote(path)
        if decoded == path:
            break
        path = decoded
    path = re.sub(r"/+", "/", path)
    path = quote(path, safe="/!$&'()*+,;=:@-._~%")
    if parsed.query:
        path += "?" + parsed.query
    return host, path


def hash_expressions(url: str) -> set[bytes]:
    host, path = _canonical_parts(url)
    labels = host.split(".")
    hosts = {host}
    try:
        ipaddress.ip_address(host)
    except ValueError:
        for length in range(2, min(5, len(labels)) + 1):
            hosts.add(".".join(labels[-length:]))
    paths = {"/", path}
    without_query = path.split("?", 1)[0]
    paths.add(without_query)
    parts = without_query.split("/")
    for count in range(1, min(5, len(parts))):
        prefix = "/".join(parts[:count + 1])
        if not prefix.endswith("/"):
            prefix += "/"
        paths.add(prefix)
    return {hashlib.sha256((host_part + path_part).encode()).digest()
            for host_part in hosts for path_part in paths}


class Reputation:
    def __init__(self):
        self._cache: dict[bytes, tuple[float, list[dict]]] = {}
        self._lock = threading.Lock()

    def check(self, url: str) -> dict:
        host, _ = _canonical_parts(url)
        key = get("safe_browsing_api_key")
        if not key:
            return {"status": "unconfigured", "host": host, "threats": []}
        hashes = hash_expressions(url)
        prefixes = {value[:4] for value in hashes}
        now = time.monotonic()
        with self._lock:
            missing = [prefix for prefix in prefixes
                       if prefix not in self._cache or self._cache[prefix][0] <= now]
        if missing:
            params = [("hashPrefixes", base64.b64encode(prefix).decode()) for prefix in missing]
            params.append(("key", key))
            try:
                result = request_json("https://safebrowsing.googleapis.com/v5/hashes:search?"
                                      + urlencode(params), timeout=10)
            except RemoteError:
                return {"status": "unavailable", "host": host, "threats": []}
            duration = result.get("cacheDuration", "300s")
            try:
                seconds = max(1.0, min(86400.0, float(duration.removesuffix("s"))))
            except ValueError:
                seconds = 300.0
            grouped = {prefix: [] for prefix in missing}
            for entry in result.get("fullHashes", []):
                try:
                    full_hash = base64.b64decode(entry["fullHash"], validate=True)
                except (KeyError, ValueError, binascii.Error):
                    continue
                if len(full_hash) == 32 and full_hash[:4] in grouped:
                    grouped[full_hash[:4]].append({"hash": full_hash,
                                                    "details": entry.get("fullHashDetails", [])})
            with self._lock:
                for prefix in missing:
                    self._cache[prefix] = (time.monotonic() + seconds, grouped[prefix])
        threats = set()
        with self._lock:
            entries = [entry for prefix in prefixes for entry in self._cache[prefix][1]]
        for entry in entries:
            if entry["hash"] not in hashes:
                continue
            for detail in entry["details"]:
                attributes = set(detail.get("attributes", []))
                threat_type = detail.get("threatType", "")
                if threat_type in {"MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE"} \
                        and attributes <= {"CANARY", "FRAME_ONLY"} \
                        and "CANARY" not in attributes and "FRAME_ONLY" not in attributes:
                    threats.add(threat_type)
        return {"status": "malicious" if threats else "no_match",
                "host": host, "threats": sorted(threats)}
