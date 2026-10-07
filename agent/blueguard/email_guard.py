from __future__ import annotations

import base64
import hashlib
import html
import json
import re
import secrets as std_secrets
import threading
import time
import webbrowser
from html.parser import HTMLParser
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import parse_qs, urlencode, urlsplit
from urllib.request import Request, urlopen

from . import secrets
from .config import Settings
from .http_client import RemoteError, request_json
from .policy import decide
from .reputation import Reputation
from .storage import Store

GMAIL_BASE = "https://gmail.googleapis.com/gmail/v1/users/me"
TOKEN_URL = "https://oauth2.googleapis.com/token"
AUTH_URL = "https://accounts.google.com/o/oauth2/v2/auth"
SCOPE = "https://www.googleapis.com/auth/gmail.readonly"
URL_RE = re.compile(r"https?://[^\s<>\"']+", re.I)
PASSWORD_RE = re.compile(r"\b(password|verify your account|sign[ -]?in|login|one[ -]?time code)\b", re.I)


class LinkParser(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.links: list[tuple[str, str]] = []
        self._href: str | None = None
        self._text: list[str] = []
        self._skip = 0

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag in {"script", "style"}:
            self._skip += 1
        if tag == "a":
            self._href = dict(attrs).get("href")
            self._text = []

    def handle_endtag(self, tag: str) -> None:
        if tag in {"script", "style"}:
            self._skip = max(0, self._skip - 1)
        if tag == "a" and self._href:
            self.links.append((self._href, "".join(self._text).strip()))
            self._href = None
            self._text = []

    def handle_data(self, data: str) -> None:
        if not self._skip and self._href:
            self._text.append(data)


def _decode(value: str) -> str:
    try:
        return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4)).decode("utf-8", errors="replace")
    except (ValueError, UnicodeError):
        return ""


def _message_parts(payload: dict, max_bytes: int) -> tuple[str, list[dict]]:
    bodies: list[str] = []
    attachments: list[dict] = []

    def visit(part: dict) -> None:
        mime = part.get("mimeType", "")
        filename = part.get("filename", "")
        body = part.get("body", {})
        if filename:
            attachments.append({"name": filename[:120], "mime": mime[:100],
                                "size": body.get("size", 0)})
            return
        if mime in {"text/plain", "text/html"} and body.get("data"):
            bodies.append(_decode(body["data"])[:max_bytes])
        for child in part.get("parts", []):
            visit(child)

    visit(payload)
    return "\n".join(bodies)[:max_bytes], attachments


def inspect_message(message: dict, reputation: Reputation, max_bytes: int) -> dict:
    payload = message.get("payload", {})
    headers = {entry["name"].lower(): entry.get("value", "")
               for entry in payload.get("headers", []) if entry.get("name")}
    body, attachments = _message_parts(payload, max_bytes)
    sender = headers.get("from", "")
    reply = headers.get("reply-to", "")
    subject = headers.get("subject", "")
    evidence: list[dict] = []
    sender_match = re.search(r"[\w.+-]+@([\w.-]+)", sender)
    reply_match = re.search(r"[\w.+-]+@([\w.-]+)", reply)
    sender_domain = sender_match.group(1).lower() if sender_match else "unknown"
    if reply_match and reply_match.group(1).lower() != sender_domain:
        evidence.append({"source": "headers", "code": "reply_to_mismatch",
                         "detail": "Reply-To uses a different domain"})
    auth = headers.get("authentication-results", "").lower()
    for method in ("spf", "dkim", "dmarc"):
        if re.search(rf"\b{method}\s*=\s*(fail|softfail)", auth):
            evidence.append({"source": "headers", "code": "auth_fail",
                             "detail": f"{method.upper()} failed"})
    if PASSWORD_RE.search(body):
        evidence.append({"source": "content", "code": "credential_request",
                         "detail": "Message asks for account access or verification"})
    parser = LinkParser()
    parser.feed(body)
    urls = {match.rstrip(".,);]") for match in URL_RE.findall(body)}
    urls.update(href for href, _ in parser.links if href.lower().startswith(("http://", "https://")))
    for href, text in parser.links:
        visible = URL_RE.search(text)
        if visible:
            try:
                if urlsplit(visible.group()).hostname != urlsplit(href).hostname:
                    evidence.append({"source": "content", "code": "display_link_mismatch",
                                     "detail": "Link text and destination use different hosts"})
            except ValueError:
                pass
    url_results = []
    for url in list(urls)[:20]:
        try:
            result = reputation.check(url)
        except ValueError:
            continue
        url_results.append(result)
        if result["status"] == "malicious":
            evidence.append({"source": "safe_browsing", "code": "known_malicious_url",
                             "detail": result["host"]})
    for attachment in attachments:
        if re.search(r"\.(exe|scr|js|vbs|sh|desktop|appimage)$", attachment["name"], re.I):
            evidence.append({"source": "attachment", "code": "suspicious_attachment",
                             "detail": "Executable or script attachment"})
    return {"message_id": message.get("id", ""), "subject": subject[:100],
            "sender_domain": sender_domain, "evidence": evidence,
            "attachments": attachments, "urls": url_results}


class Gmail:
    def __init__(self, settings: Settings, store: Store, reputation: Reputation):
        self.settings = settings
        self.store = store
        self.reputation = reputation
        self._access_token = ""
        self._expires_at = 0.0
        self._oauth_status = "idle"
        self._lock = threading.Lock()

    def status(self) -> dict:
        return {"connected": bool(secrets.get("gmail_refresh_token")),
                "oauth_status": self._oauth_status,
                "last_scan": self.store.get_state("gmail_last_scan")}

    def connect(self) -> dict:
        if not self.settings.gmail_client_id:
            raise ValueError("Set the Gmail OAuth client ID first")
        with self._lock:
            if self._oauth_status == "waiting":
                return {"status": "waiting"}
            self._oauth_status = "waiting"
        verifier = std_secrets.token_urlsafe(64)
        challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).decode().rstrip("=")
        state = std_secrets.token_urlsafe(32)
        callback: dict[str, str] = {}

        class Handler(BaseHTTPRequestHandler):
            def do_GET(self) -> None:
                query = parse_qs(urlsplit(self.path).query)
                callback["state"] = query.get("state", [""])[0]
                callback["code"] = query.get("code", [""])[0]
                callback["error"] = query.get("error", [""])[0]
                ok = callback["state"] == state and bool(callback["code"])
                content = b"Bluely connected. You may close this tab." if ok else b"Bluely connection failed."
                self.send_response(200 if ok else 400)
                self.send_header("Content-Type", "text/plain; charset=utf-8")
                self.send_header("Content-Length", str(len(content)))
                self.end_headers()
                self.wfile.write(content)

            def log_message(self, *_args: object) -> None:
                pass

        server = HTTPServer(("127.0.0.1", 0), Handler)
        server.timeout = 180
        redirect = f"http://127.0.0.1:{server.server_port}/callback"
        params = {"client_id": self.settings.gmail_client_id,
                  "redirect_uri": redirect, "response_type": "code", "scope": SCOPE,
                  "access_type": "offline", "prompt": "consent", "state": state,
                  "code_challenge": challenge, "code_challenge_method": "S256"}
        url = AUTH_URL + "?" + urlencode(params)

        def complete() -> None:
            try:
                server.handle_request()
                if callback.get("state") != state or not callback.get("code"):
                    raise ValueError("OAuth was cancelled, rejected, or timed out")
                token = self._token_request({"client_id": self.settings.gmail_client_id,
                                             "client_secret": secrets.get("gmail_client_secret"),
                                             "code": callback["code"], "code_verifier": verifier,
                                             "redirect_uri": redirect,
                                             "grant_type": "authorization_code"})
                refresh = token.get("refresh_token", "")
                if not refresh:
                    raise ValueError("Google did not return a refresh token")
                secrets.set_secret("gmail_refresh_token", refresh)
                self._access_token = token["access_token"]
                self._expires_at = time.monotonic() + int(token.get("expires_in", 3600)) - 60
                self._oauth_status = "connected"
                self.store.audit("gmail_connect", "user", "success", {})
            except Exception as error:
                self._oauth_status = f"error: {type(error).__name__}"
                self.store.audit("gmail_connect", "user", "error", {"type": type(error).__name__})
            finally:
                server.server_close()

        threading.Thread(target=complete, daemon=True).start()
        webbrowser.open(url)
        return {"status": "waiting", "authorization_url": url}

    @staticmethod
    def _token_request(form: dict) -> dict:
        request = Request(TOKEN_URL, data=urlencode(form).encode(),
                          headers={"Content-Type": "application/x-www-form-urlencoded"})
        try:
            with urlopen(request, timeout=20) as response:
                return json.load(response)
        except Exception as error:
            raise RemoteError("Gmail authentication failed") from error

    def _token(self) -> str:
        if self._access_token and time.monotonic() < self._expires_at:
            return self._access_token
        refresh = secrets.get("gmail_refresh_token")
        if not refresh:
            raise ValueError("Gmail is not connected")
        token = self._token_request({"client_id": self.settings.gmail_client_id,
                                     "client_secret": secrets.get("gmail_client_secret"),
                                     "refresh_token": refresh, "grant_type": "refresh_token"})
        self._access_token = token["access_token"]
        self._expires_at = time.monotonic() + int(token.get("expires_in", 3600)) - 60
        return self._access_token

    def _get(self, path: str, params: dict | None = None) -> dict:
        url = GMAIL_BASE + path + ("?" + urlencode(params) if params else "")
        return request_json(url, headers={"Authorization": "Bearer " + self._token()})

    def scan(self, explain_event=None) -> dict:
        checkpoint = self.store.get_state("gmail_last_scan")
        since = max(int(checkpoint) - 300, int(time.time()) - 7 * 86400) if checkpoint else int(time.time()) - 7 * 86400
        page_token = ""
        count = alerts = 0
        max_date = int(checkpoint or 0)
        while count < 500:
            params = {"q": f"after:{since}", "maxResults": min(100, 500 - count)}
            if page_token:
                params["pageToken"] = page_token
            page = self._get("/messages", params)
            for summary in page.get("messages", []):
                if self.store.is_message_processed(summary["id"]):
                    continue
                message = self._get("/messages/" + summary["id"], {"format": "full"})
                count += 1
                max_date = max(max_date, int(message.get("internalDate", "0")) // 1000)
                finding = inspect_message(message, self.reputation, self.settings.max_message_bytes)
                decision = decide(finding["evidence"])
                if decision.risk >= 30:
                    event = self.store.add_event("email", finding["subject"] or finding["sender_domain"],
                                                 decision.risk, decision.verdict, finding["evidence"],
                                                 source_key="gmail:" + summary["id"])
                    alerts += 1
                    if explain_event and not event["explanation"]:
                        explain_event(event)
                self.store.mark_message_processed(summary["id"])
            page_token = page.get("nextPageToken", "")
            if not page_token:
                break
        if not page_token:
            self.store.set_state("gmail_last_scan", str(max(max_date, int(time.time()) - 300)))
        self.store.audit("gmail_scan", "schedule_or_user", "success", {"messages": count, "alerts": alerts})
        return {"messages": count, "alerts": alerts, "truncated": bool(page_token)}
