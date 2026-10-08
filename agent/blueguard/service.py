from __future__ import annotations

import json
import hashlib
import os
import errno
import shutil
import socket
import socketserver
import sys
import threading
import time
import uuid
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from pathlib import Path

from . import secrets
from .assistant import parse_request
from .config import DATA_DIR, SOCKET_PATH, Settings
from .email_guard import Gmail
from .models import chat_assistant, codex_status, draft_assistant_note, explain, suggest_assistant_prompts, summarize_event
from .policy import decide
from .reputation import Reputation
from .scanners import allowed_download, scan_file, sha256_file
from .storage import Store
from .virustotal import VirusTotal, public_url


class Agent:
    def __init__(self):
        self.settings = Settings.load()
        self.store = Store()
        self.reputation = Reputation()
        self.virustotal = VirusTotal()
        self.gmail = Gmail(self.settings, self.store, self.reputation)
        self._gmail_lock = threading.Lock()
        self._scans: set[str] = set()
        self._scan_lock = threading.Lock()
        self._model_pool = ThreadPoolExecutor(max_workers=2, thread_name_prefix="blueguard-model")
        self._assistant_pool = ThreadPoolExecutor(max_workers=2, thread_name_prefix="bluely-assistant")
        self._assistant_lock = threading.Lock()
        self._assistant_jobs = {}
        self._scan_pool = ThreadPoolExecutor(max_workers=2, thread_name_prefix="blueguard-scan")
        self._scan_jobs: dict[str, tuple[float, object]] = {}
        self._scan_paths: dict[str, str] = {}
        self._scan_job_lock = threading.Lock()
        if self.store.get_state("alert_summary_version") != "2":
            self._model_pool.submit(self._repair_alert_summaries)

    def _repair_alert_summaries(self) -> None:
        try:
            for event in self.store.list_all_events():
                explanation, model_used = summarize_event(self.settings, event["kind"], event["risk"],
                                                           event["verdict"], event["evidence"], event["subject"])
                self.store.update_explanation(event["id"], explanation, model_used)
            self.store.set_state("alert_summary_version", "2")
        except Exception as error:
            self.store.audit("alert_summary_repair", "selected_provider", "error",
                             {"type": type(error).__name__})

    def _queue_assistant_reply(self, result: dict, history: list[dict] | None = None) -> dict:
        job_id = uuid.uuid4().hex
        snapshot = replace(self.settings)
        future = (self._assistant_pool.submit(chat_assistant, snapshot, history)
                  if history is not None else self._assistant_pool.submit(
                      draft_assistant_note, snapshot, result["kind"], result["status"],
                      result.get("result", result)))
        with self._assistant_lock:
            now = time.monotonic()
            self._assistant_jobs = {key: value for key, value in self._assistant_jobs.items()
                                    if now - value[0] < 600}
            self._assistant_jobs[job_id] = (now, future)
        return {**result, "reply_id": job_id}

    def _assistant_reply(self, job_id: str) -> dict:
        with self._assistant_lock:
            item = self._assistant_jobs.get(job_id)
        if not item:
            return {"status": "expired"}
        future = item[1]
        if not future.done():
            return {"status": "pending"}
        with self._assistant_lock:
            self._assistant_jobs.pop(job_id, None)
        try:
            note, model_used = future.result()
            if isinstance(note, list):
                return {"status": "ready", "suggestions": note, "model_used": model_used}
            return {"status": "ready", "note": note, "model_used": model_used}
        except Exception:
            return {"status": "unavailable"}

    def _explain(self, event: dict) -> None:
        def run() -> None:
            try:
                explanation, model_used = summarize_event(self.settings, event["kind"], event["risk"],
                                                           event["verdict"], event["evidence"], event["subject"])
                self.store.update_explanation(event["id"], explanation, model_used)
            except Exception as error:
                self.store.audit("model_explain", "selected_provider", "unavailable",
                                 {"type": type(error).__name__}, event["id"])
        self._model_pool.submit(run)

    def _register_scan(self, future, scan_id: str | None = None) -> str:
        scan_id = scan_id or uuid.uuid4().hex
        with self._scan_job_lock:
            now = time.monotonic()
            self._scan_jobs = {key: value for key, value in self._scan_jobs.items()
                               if now - value[0] < 600}
            self._scan_jobs[scan_id] = (now, future)
        return scan_id

    def _assistant_scan_result(self, scan_id: str) -> dict:
        with self._scan_job_lock:
            item = self._scan_jobs.get(scan_id)
        if not item or time.monotonic() - item[0] >= 600:
            return {"status": "expired"}
        future = item[1]
        if not future.done():
            return {"status": "pending"}
        try:
            result = future.result()
        except Exception:
            return {"status": "error"}
        findings = [self.store.get_event(event_id) for event_id in result.get("finding_ids", [])]
        findings = [event for event in findings if event]
        top = max(findings, key=lambda event: (event["risk"], event["created_at"])) if findings else None
        return {"status": result.get("status", "completed"), "kind": result.get("kind", "email"),
                "messages": result.get("messages", 0), "findings": len(findings),
                "truncated": result.get("truncated", False),
                "top_finding": ({"id": top["id"], "kind": top["kind"], "subject": top["subject"],
                                 "risk": top["risk"], "verdict": top["verdict"],
                                 "summary": top["explanation"] or
                                 f"Bluely policy rated this finding {top['verdict']} ({top['risk']}/100)."}
                                if top else None)}

    def _gmail_scan(self, acquired: bool = False) -> dict:
        if not acquired and not self._gmail_lock.acquire(blocking=False):
            return {"status": "running"}
        try:
            return {**self.gmail.scan(self._explain), "kind": "email"}
        except Exception as error:
            self.store.audit("gmail_scan", "schedule_or_user", "error", {"type": type(error).__name__})
            return {"status": "error", "kind": "email", "messages": 0, "finding_ids": []}
        finally:
            self._gmail_lock.release()

    def _download_scan(self, path: str, url: str) -> dict:
        try:
            result = scan_file(path, self.settings)
            evidence = result["evidence"]
            vt_status = "disabled" if not self.settings.virustotal_file_lookups else "skipped"
            if result.get("sha256") and self.settings.virustotal_file_lookups:
                vt_result = self.virustotal.lookup_file(result["sha256"])
                vt_status = vt_result["status"]
                if vt_status in {"malicious", "suspicious"}:
                    evidence.append({"source": "virustotal",
                                     "code": "vt_malicious_file" if vt_status == "malicious" else "vt_suspicious_file",
                                     "detail": f"{vt_result['malicious']} malicious, {vt_result['suspicious']} suspicious detections"})
            try:
                reputation = self.reputation.check(url) if url else {"status": "unconfigured", "threats": []}
            except ValueError:
                reputation = {"status": "unavailable", "threats": []}
            if reputation["status"] == "malicious":
                evidence.append({"source": "safe_browsing", "code": "known_malicious_url",
                                 "detail": reputation["host"]})
            decision = decide(evidence)
            evidence.append({"source": "scan", "code": "scan_status", "detail": result["status"]})
            for tool, status in result.get("tools", {}).items():
                evidence.append({"source": tool, "code": "tool_status", "detail": status})
            evidence.append({"source": "virustotal", "code": "tool_status", "detail": vt_status})
            if result["sha256"]:
                evidence.append({"source": "file", "code": "sha256", "detail": result["sha256"]})
            event = self.store.add_event("download", result["path"], decision.risk,
                                         decision.verdict, evidence,
                                         source_key="download:" + result["path"] + ":" + result["sha256"])
            self.store.audit("download_scan", "browser_event", "success",
                             {"status": result["status"], "tools": result.get("tools", {})}, event["id"])
            if decision.risk >= 30:
                self._explain(event)
            return {"status": "completed", "kind": "file", "messages": 1, "finding_ids": [event["id"]]}
        except Exception as error:
            self.store.audit("download_scan", "browser_event", "error",
                             {"type": type(error).__name__})
            return {"status": "error", "kind": "file", "messages": 0, "finding_ids": []}
        finally:
            with self._scan_lock:
                self._scans.discard(path)
                self._scan_paths.pop(path, None)

    def dispatch(self, method: str, params: dict) -> dict | list:
        if method == "assistant_reply":
            return self._assistant_reply(str(params.get("reply_id", "")))
        if method == "assistant_suggestions":
            if self.settings.model_provider not in {"ollama", "llama_cpp", "codex"}:
                return {"status": "local_model_required"}
            previous = params.get("previous", [])
            if not isinstance(previous, list) or len(previous) > 9 or any(
                    not isinstance(item, str) or len(item) > 120 for item in previous):
                raise ValueError("Invalid previous suggestions")
            future = self._assistant_pool.submit(suggest_assistant_prompts, replace(self.settings),
                                                 previous, self.gmail.status()["connected"])
            job_id = uuid.uuid4().hex
            with self._assistant_lock:
                now = time.monotonic()
                self._assistant_jobs = {key: value for key, value in self._assistant_jobs.items()
                                        if now - value[0] < 600}
                self._assistant_jobs[job_id] = (now, future)
            return {"status": "pending", "reply_id": job_id}
        if method == "assistant_scan_result":
            return self._assistant_scan_result(str(params.get("scan_id", "")))
        if method == "assistant_request":
            parsed = parse_request(str(params.get("message", "")))
            intent = parsed["intent"]
            if intent == "email":
                if not self.gmail.status()["connected"]:
                    return self._queue_assistant_reply({"kind": "email", "status": "not_connected",
                                                        "message": "Gmail is not connected. Log in from the top bar, then ask me to check your email again."})
                result = self.dispatch("gmail_scan", {})
                return {"kind": "email", "status": result["status"], "scan_id": result.get("scan_id"),
                        "message": "Checking Gmail now. I'll show the scan result here." if result["status"] == "started"
                        else "An email scan is already running. Its findings will appear in Alerts."}
            if intent in {"url", "virustotal_domain", "virustotal_url"}:
                if intent == "url":
                    try:
                        safe_result = self.dispatch("check_url", {"url": parsed["url"]})
                    except Exception:
                        safe_result = {"status": "unavailable", "host": parsed["url"]}
                    try:
                        vt_result = (self.virustotal.lookup_url(parsed["url"], confirmed=True)
                                     if hasattr(self, "virustotal") else {"status": "unconfigured"})
                    except Exception:
                        vt_result = {"status": "unavailable"}
                    sources = {"safe_browsing": safe_result, "virustotal": vt_result}
                    usable = [item for item in sources.values() if item.get("status") not in {"unconfigured", "unavailable"}]
                    if not usable:
                        status = "unavailable" if any(item.get("status") == "unavailable" for item in sources.values()) else "unconfigured"
                    elif any(item.get("status") == "malicious" for item in usable):
                        status = "malicious"
                    elif any(item.get("status") in {"suspicious", "low_signal"} for item in usable):
                        status = "suspicious"
                    else:
                        status = "no_match"
                    safe_status = safe_result.get("status", "unavailable")
                    vt_status = vt_result.get("status", "unavailable")
                    returned = []
                    if safe_status not in {"unconfigured", "unavailable"}:
                        returned.append(f"Safe Browsing returned {safe_status.replace('_', ' ')}")
                    if vt_status not in {"unconfigured", "unavailable"}:
                        returned.append(f"VirusTotal returned {vt_status.replace('_', ' ')}")
                    evidence_summary = " ".join(returned) if returned else "No reputation source returned a result"
                    message = (f"URL investigation complete. {evidence_summary}. "
                               + ("Do not open this URL." if status == "malicious" else
                                  "Treat this URL cautiously and review the technical findings." if status == "suspicious" else
                                  "No reputation match was returned; this does not prove safety." if returned else
                                  "Retry the investigation when a reputation source is available."))
                    merged = {"status": status, "kind": "url", "malicious": vt_result.get("malicious", 0),
                              "suspicious": vt_result.get("suspicious", 0), "sources": sources}
                    if safe_status not in {"unconfigured", "unavailable"}:
                        merged["safe_browsing_status"] = safe_status
                    if vt_status not in {"unconfigured", "unavailable"}:
                        merged["virustotal_status"] = vt_status
                    return self._queue_assistant_reply({"kind": "url", "status": status,
                                                        "message": message, "result": merged})
                method = "check_url" if intent == "url" else "virustotal_url" if intent == "virustotal_url" else "virustotal_domain"
                result = self.dispatch(method, {"url": parsed["url"], "confirmed": intent == "virustotal_url"})
                status = result["status"]
                source = "VirusTotal" if intent != "url" else "Safe Browsing"
                engine_counts = (f" Engines: {result.get('malicious', 0)} malicious, "
                                 f"{result.get('suspicious', 0)} suspicious, "
                                 f"{result.get('harmless', 0)} harmless, "
                                 f"{result.get('undetected', 0)} undetected."
                                 if intent != "url" and "malicious" in result else "")
                if status == "malicious":
                    message = f"{source} reports malicious detections for {result.get('host', result.get('id', parsed['url']))}.{engine_counts} Do not open it."
                elif status == "suspicious":
                    message = f"{source} reports suspicious detections for {result['id']}.{engine_counts} Treat it with caution."
                elif status == "no_match":
                    message = f"No match was found in {source}.{engine_counts} That does not prove the site is safe."
                elif status == "not_found":
                    message = "VirusTotal has no report for this domain. That does not prove it is safe."
                elif status == "no_data":
                    message = "VirusTotal has no analysis votes for this domain. That does not prove it is safe."
                elif status == "low_signal":
                    message = "VirusTotal has a small number of suspicious votes. Review the site with caution."
                elif status == "unconfigured":
                    message = f"{source} is not configured. Add its API key in Integrations to check this site."
                elif status == "rate_limited":
                    message = "VirusTotal's lookup limit was reached. Try again shortly."
                else:
                    message = f"{source} could not verify this site right now."
                return self._queue_assistant_reply({"kind": intent, "status": status,
                                                    "message": message, "result": result})
            if intent == "virustotal_submit_url":
                result = self.dispatch("virustotal_submit_url", {"url": parsed["url"], "confirmed": True})
                status = result["status"]
                message = (f"VirusTotal accepted the URL for analysis. Analysis ID: {result.get('analysis_id', 'pending')}."
                           if status == "queued" else f"VirusTotal could not submit the URL ({status.replace('_', ' ')}).")
                return self._queue_assistant_reply({"kind": intent, "status": status, "message": message, "result": result})
            if intent == "virustotal_file":
                result = self.dispatch("virustotal_file", {"sha256": parsed["sha256"]})
                status = result["status"]
                message = (f"VirusTotal reports {result.get('malicious', 0)} malicious and {result.get('suspicious', 0)} suspicious engines for that hash."
                           if status in {"malicious", "suspicious", "low_signal", "no_match"}
                           else f"VirusTotal could not check that hash ({status.replace('_', ' ')}).")
                return self._queue_assistant_reply({"kind": intent, "status": status, "message": message, "result": result})
            if intent == "virustotal_ip":
                result = self.dispatch("virustotal_ip", {"ip": parsed["ip"]})
                status = result["status"]
                message = f"VirusTotal reports {result.get('malicious', 0)} malicious and {result.get('suspicious', 0)} suspicious engines for that IP." if status in {"malicious", "suspicious", "low_signal", "no_match"} else f"VirusTotal could not check that IP ({status.replace('_', ' ')})."
                return self._queue_assistant_reply({"kind": intent, "status": status, "message": message, "result": result})
            if intent == "scan_download":
                result = self.dispatch("scan_download", {"path": parsed["path"]})
                status = result["status"]
                return {"kind": intent, "status": status, "scan_id": result.get("scan_id"),
                        "message": "Scanning the file now. I'll show the result here." if status == "queued"
                        else "That file is already being scanned. Its finding will appear in Alerts." if not result.get("scan_id")
                        else "That file is already being scanned. I'll show its result here."}
            if intent == "virustotal_upload_file":
                result = self.dispatch("virustotal_upload_file", {"path": parsed["path"], "confirmed": True})
                status = result["status"]
                message = (f"VirusTotal accepted the file for analysis. Analysis ID: {result.get('analysis_id', 'pending')}."
                           if status == "queued" else f"VirusTotal could not upload the file ({status.replace('_', ' ')}).")
                return self._queue_assistant_reply({"kind": intent, "status": status, "message": message, "result": result})
            if intent == "virustotal_analysis":
                result = self.dispatch("virustotal_analysis", {"analysis_id": parsed["analysis_id"]})
                status = result["status"]
                message = (f"VirusTotal analysis is {status}." if status != "completed" else
                           f"VirusTotal analysis is complete: {result.get('malicious', 0)} malicious, {result.get('suspicious', 0)} suspicious, {result.get('harmless', 0)} harmless.")
                return self._queue_assistant_reply({"kind": intent, "status": status, "message": message, "result": result})
            history = params.get("history", [])
            if not isinstance(history, list):
                raise ValueError("Invalid chat history")
            cleaned = [{"role": item.get("role"), "content": str(item.get("content", ""))}
                       for item in history[-11:] if isinstance(item, dict)]
            cleaned.append({"role": "user", "content": str(params.get("message", ""))[:2000]})
            if self.settings.model_provider in {"ollama", "llama_cpp", "codex"}:
                return self._queue_assistant_reply({"kind": "chat", "status": "pending",
                                                    "message": ""}, cleaned)
            return {"kind": "chat", "status": "local_model_required",
                    "message": "Select Ollama, llama.cpp, or a signed-in Codex CLI in Models for general conversation. API cloud providers receive only coded security results."}
        if method == "status":
            if sys.platform == "win32":
                from .windows_pipe import SCANNER_PIPE, request as pipe_request
                try:
                    defender_ready = pipe_request(SCANNER_PIPE, {"method": "status"}, 1000).get("ready", False)
                except (OSError, ValueError):
                    defender_ready = False
                tools = {"defender": defender_ready, "yara": bool(shutil.which("yara"))}
            else:
                tools = {name: bool(shutil.which(name)) for name in ("clamscan", "yara", "file")}
            return {"version": "0.1.0", "gmail": self.gmail.status(),
                    "unread_alerts": self.store.unread_alert_count(),
                    "tools": tools,
                    "reputation_configured": bool(secrets.get("safe_browsing_api_key")),
                    "virustotal_configured": bool(secrets.get("virustotal_api_key")),
                    "scan_queue": len(self._scans)}
        if method == "settings_get":
            return {"model_provider": self.settings.model_provider,
                    "model_name": self.settings.model_name,
                    "model_endpoint": self.settings.model_endpoint,
                    "gmail_client_id": self.settings.gmail_client_id,
                    "downloads_dir": self.settings.downloads_dir,
                    "email_interval_minutes": self.settings.email_interval_minutes,
                    "max_scan_bytes": self.settings.max_scan_bytes,
                    "virustotal_file_lookups": self.settings.virustotal_file_lookups}
        if method == "settings_update":
            self.settings.update(params)
            self.settings.save()
            self.store.audit("settings_update", "desktop_user", "success", {"keys": sorted(params)})
            return {"saved": True}
        if method == "extension_register":
            if sys.platform != "win32":
                raise ValueError("Use bluely setup --extension-id on Linux")
            from .cli import setup_windows
            setup_windows(str(params.get("extension_id", "")))
            return {"saved": True}
        if method == "model_test":
            _, model_used = explain(self.settings, "connection_test", 0, "low", [],
                                    "Bluely model connection test")
            return {"model_used": model_used, "response": "Model API responded successfully."}
        if method == "codex_status":
            return codex_status()
        if method == "secrets_status":
            return secrets.availability()
        if method == "secret_set":
            name = str(params.get("name", ""))
            if name == "gmail_refresh_token":
                raise ValueError("Gmail refresh token is managed by OAuth")
            secrets.set_secret(name, str(params.get("value", "")))
            self.store.audit("secret_set", "desktop_user", "success", {"name": name})
            return {"saved": True}
        if method == "virustotal_disconnect":
            secrets.set_secret("virustotal_api_key", "")
            self.store.audit("virustotal_disconnect", "desktop_user", "success", {})
            return {"status": "disconnected"}
        if method == "gmail_connect":
            return self.gmail.connect()
        if method == "gmail_disconnect":
            return self.gmail.disconnect()
        if method == "alerts_mark_seen":
            return {"unread_alerts": self.store.mark_alerts_seen(str(params.get("through", "")))}
        if method == "gmail_scan":
            if not self._gmail_lock.acquire(blocking=False):
                return {"status": "running"}
            try:
                future = self._scan_pool.submit(self._gmail_scan, True)
            except Exception:
                self._gmail_lock.release()
                raise
            return {"status": "started", "scan_id": self._register_scan(future)}
        if method == "check_url":
            url = str(params.get("url", ""))[:4096]
            result = self.reputation.check(url)
            if result["status"] == "malicious":
                evidence = [{"source": "safe_browsing", "code": "known_malicious_url",
                             "detail": result["host"]}]
                decision = decide(evidence)
                event = self.store.add_event("url", result["host"], decision.risk,
                                             decision.verdict, evidence,
                                             source_key="url:" + url)
                self._explain(event)
            return result
        if method == "virustotal_domain":
            url = str(params.get("url", ""))[:4096]
            result = self.virustotal.lookup_domain(url)
            self.store.audit("virustotal_domain", "explicit_user_request", result["status"],
                             {"domain": result["id"]})
            if result["status"] == "malicious":
                evidence = [{"source": "virustotal", "code": "vt_malicious_domain",
                             "detail": f"{result['malicious']} malicious, {result['suspicious']} suspicious detections"}]
                decision = decide(evidence)
                event = self.store.add_event("url", result["id"], decision.risk,
                                             decision.verdict, evidence,
                                             source_key="vt-domain:" + result["id"])
                self._explain(event)
            return result
        if method == "virustotal_url":
            url = str(params.get("url", ""))
            _, host = public_url(url)
            result = self.virustotal.lookup_url(url, params.get("confirmed") is True)
            self.store.audit("virustotal_url", "explicit_user_confirmation", result["status"], {"host": host})
            if result["status"] == "malicious":
                evidence = [{"source": "virustotal", "code": "vt_malicious_url",
                             "detail": f"{result['malicious']} malicious, {result['suspicious']} suspicious detections"}]
                decision = decide(evidence)
                event = self.store.add_event("url", host, decision.risk, decision.verdict, evidence,
                                             source_key="vt-url:" + hashlib.sha256(url.encode()).hexdigest())
                self._explain(event)
            return result
        if method == "virustotal_ip":
            result = self.virustotal.lookup_ip(str(params.get("ip", "")))
            self.store.audit("virustotal_ip", "explicit_user_request", result["status"], {"ip": result["id"]})
            return result
        if method == "virustotal_file":
            result = self.virustotal.lookup_file(str(params.get("sha256", "")))
            self.store.audit("virustotal_file", "explicit_user_request", result["status"], {"sha256": result["id"]})
            return result
        if method == "virustotal_submit_url":
            url = str(params.get("url", ""))
            result = self.virustotal.submit_url(url, params.get("confirmed") is True)
            self.store.audit("virustotal_submit_url", "explicit_user_confirmation", result["status"], {"host": result["id"]})
            return result
        if method == "virustotal_upload_file":
            path = str(params.get("path", ""))
            allowed_download(path, self.settings)
            result = self.virustotal.upload_file(path, params.get("confirmed") is True)
            self.store.audit("virustotal_upload_file", "explicit_user_confirmation", result["status"],
                             {"sha256": result.get("sha256")})
            return result
        if method == "virustotal_analysis":
            result = self.virustotal.analysis(str(params.get("analysis_id", "")))
            self.store.audit("virustotal_analysis", "explicit_user_request", result["status"], {})
            return result
        if method == "scan_download":
            path = str(params.get("path", ""))
            allowed_download(path, self.settings)
            with self._scan_lock:
                if path in self._scans:
                    return {"status": "running", "scan_id": self._scan_paths.get(path)}
                self._scans.add(path)
                scan_id = uuid.uuid4().hex
                self._scan_paths[path] = scan_id
            try:
                future = self._scan_pool.submit(self._download_scan, path, str(params.get("url", ""))[:4096])
            except Exception:
                with self._scan_lock:
                    self._scans.discard(path)
                    self._scan_paths.pop(path, None)
                raise
            return {"status": "queued", "scan_id": self._register_scan(future, scan_id)}
        if method == "events_list":
            return self.store.list_events(int(params.get("limit", 100)))
        if method == "audit_list":
            return self.store.list_audit(int(params.get("limit", 100)))
        if method == "quarantine_list":
            return self.store.list_quarantine()
        if method == "quarantine":
            return self._quarantine(str(params.get("event_id", "")), params.get("confirmed") is True)
        if method == "restore":
            return self._restore(str(params.get("id", "")), params.get("confirmed") is True)
        raise ValueError("Unknown method")

    def _quarantine(self, event_id: str, confirmed: bool) -> dict:
        if not confirmed:
            raise ValueError("Explicit confirmation is required")
        event = self.store.get_event(event_id)
        if not event or event["kind"] != "download" or event["status"] != "open":
            raise ValueError("Download event is not eligible")
        if not decide(event["evidence"]).quarantine_eligible:
            raise ValueError("Strong scanner evidence is required for quarantine")
        path = allowed_download(event["subject"], self.settings)
        original_hash = next((item["detail"] for item in event["evidence"]
                              if item["code"] == "sha256"), "")
        if not original_hash or sha256_file(path) != original_hash:
            raise ValueError("File changed since the scan; scan it again")
        folder = DATA_DIR / "quarantine"
        folder.mkdir(mode=0o700, parents=True, exist_ok=True)
        destination = folder / (event_id + ".bin")
        if destination.exists():
            raise ValueError("Quarantine target already exists")
        try:
            _move_verified(path, destination, original_hash)
        except OSError as error:
            raise ValueError("Cannot move file into quarantine") from error
        destination.chmod(0o600)
        record = self.store.add_quarantine(event_id, str(path), str(destination), original_hash)
        self.store.audit("quarantine", "explicit_user_confirmation", "success",
                         {"sha256": original_hash}, event_id)
        return record

    def _restore(self, record_id: str, confirmed: bool) -> dict:
        if not confirmed:
            raise ValueError("Explicit confirmation is required")
        record = self.store.get_quarantine(record_id)
        if not record or record["restored_at"]:
            raise ValueError("Quarantine record is not active")
        source = Path(record["stored_path"])
        if source.parent.resolve() != (DATA_DIR / "quarantine").resolve() or source.is_symlink():
            raise ValueError("Invalid quarantine file")
        destination = Path(record["original_path"])
        if destination.exists() or destination.is_symlink():
            raise ValueError("Original path is occupied")
        if sha256_file(source) != record["sha256"]:
            raise ValueError("Quarantined file failed integrity check")
        if not destination.parent.is_dir():
            raise ValueError("Original folder no longer exists")
        _move_verified(source, destination, record["sha256"])
        self.store.mark_restored(record_id)
        self.store.audit("restore", "explicit_user_confirmation", "success",
                         {"sha256": record["sha256"]}, record["event_id"])
        return {"restored": True, "path": str(destination)}


def _move_verified(source: Path, destination: Path, expected_hash: str) -> None:
    """Move across volumes without discarding the source before a verified copy exists."""
    try:
        os.rename(source, destination)
        return
    except OSError as error:
        if error.errno != errno.EXDEV and sys.platform != "win32":
            raise
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    try:
        descriptor = os.open(destination, flags, 0o600)
        with os.fdopen(descriptor, "wb") as output, source.open("rb") as input_file:
            shutil.copyfileobj(input_file, output, 1024 * 1024)
        if sha256_file(destination) != expected_hash or sha256_file(source) != expected_hash:
            raise ValueError("File changed while moving; retry the operation")
        source.unlink()
    except Exception:
        destination.unlink(missing_ok=True)
        raise


class Handler(socketserver.StreamRequestHandler):
    def handle(self) -> None:
        raw = self.rfile.readline(1024 * 1024 + 1)
        if len(raw) > 1024 * 1024:
            return
        try:
            response = handle_rpc(self.server.agent, json.loads(raw))
        except Exception as error:
            response = {"ok": False, "error": str(error)[:300]}
        try:
            self.wfile.write((json.dumps(response) + "\n").encode())
        except (BrokenPipeError, ConnectionResetError):
            pass


if sys.platform != "win32":
    class Server(socketserver.ThreadingUnixStreamServer):
        daemon_threads = True

        def __init__(self, path: str, agent: Agent):
            self.agent = agent
            super().__init__(path, Handler)


def handle_rpc(agent: Agent, payload: dict) -> dict:
    return {"ok": True, "result": agent.dispatch(payload["method"], payload.get("params", {}))}


def request(method: str, params: dict | None = None, timeout: float = 20) -> dict:
    if sys.platform == "win32":
        from .windows_pipe import AGENT_PIPE, request as pipe_request
        return pipe_request(AGENT_PIPE, {"method": method, "params": params or {}},
                            int(timeout * 1000))
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
        connection.settimeout(timeout)
        connection.connect(str(SOCKET_PATH))
        connection.sendall((json.dumps({"method": method, "params": params or {}}) + "\n").encode())
        data = b""
        while not data.endswith(b"\n") and len(data) < 1024 * 1024:
            part = connection.recv(65536)
            if not part:
                break
            data += part
    return json.loads(data)


def serve() -> None:
    if sys.platform != "win32":
        os.umask(0o077)
        SOCKET_PATH.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        if SOCKET_PATH.exists():
            try:
                request("status", timeout=1)
                raise RuntimeError("Bluely agent is already running")
            except (ConnectionRefusedError, FileNotFoundError, TimeoutError, OSError):
                SOCKET_PATH.unlink()
    agent = Agent()

    def schedule() -> None:
        while True:
            if secrets.get("gmail_refresh_token"):
                agent._gmail_scan()
            time.sleep(agent.settings.email_interval_minutes * 60)

    threading.Thread(target=schedule, daemon=True).start()
    try:
        if sys.platform == "win32":
            from .windows_pipe import AGENT_PIPE, serve as serve_pipe
            serve_pipe(AGENT_PIPE, lambda payload, _handle: handle_rpc(agent, payload), user_only=True)
        else:
            with Server(str(SOCKET_PATH), agent) as server:
                SOCKET_PATH.chmod(0o600)
                server.serve_forever(poll_interval=0.5)
    except KeyboardInterrupt:
        pass
    finally:
        agent._scan_pool.shutdown(wait=False, cancel_futures=True)
        agent._model_pool.shutdown(wait=False, cancel_futures=True)
        if sys.platform != "win32":
            SOCKET_PATH.unlink(missing_ok=True)
        agent.store.close()
