from __future__ import annotations

import re
from urllib.parse import urlsplit

URL_RE = re.compile(r"https?://[^\s<>\"']+", re.I)
DOMAIN_RE = re.compile(r"(?<![@\w.-])(?:[a-z0-9-]+\.)+[a-z]{2,}(?::\d+)?(?:/[^\s<>\"']*)?", re.I)
EMAIL_RE = re.compile(r"\b(email|emails|mail|gmail|inbox)\b", re.I)
CHECK_RE = re.compile(r"\b(check|scan|review|look|inspect|analy[sz]e)\b", re.I)
HASH_RE = re.compile(r"\b[a-f0-9]{64}\b", re.I)
IP_RE = re.compile(r"(?<![\w.])(?:\d{1,3}\.){3}\d{1,3}(?![\w.])")
PATH_RE = re.compile(r"(?:/home/[\w./-]+|~/[\w./-]+)")
ANALYSIS_RE = re.compile(r"\b(?:analysis|scan)\s*(?:id|:)?\s*([A-Za-z0-9_-]{8,200})\b", re.I)


def parse_request(message: str) -> dict:
    text = message.strip()[:4096]
    if not text:
        return {"intent": "unsupported"}
    analysis_match = ANALYSIS_RE.search(text)
    if analysis_match and "virus" in text.lower():
        return {"intent": "virustotal_analysis", "analysis_id": analysis_match.group(1)}
    hash_match = HASH_RE.search(text)
    if hash_match and ("virus" in text.lower() or "hash" in text.lower() or "file" in text.lower()):
        return {"intent": "virustotal_file", "sha256": hash_match.group().lower()}
    ip_match = IP_RE.search(text)
    if ip_match and ("virus" in text.lower() or "ip" in text.lower() or "check" in text.lower()):
        return {"intent": "virustotal_ip", "ip": ip_match.group()}
    path_match = PATH_RE.search(text)
    if path_match:
        if "upload" in text.lower() and ("virus" in text.lower() or re.search(r"\bvt\b", text, re.I)):
            return {"intent": "virustotal_upload_file", "path": path_match.group()}
        if "scan" in text.lower() or "file" in text.lower() or "malware" in text.lower():
            return {"intent": "scan_download", "path": path_match.group()}
    match = URL_RE.search(text) or DOMAIN_RE.search(text)
    if match:
        url = match.group().rstrip(".,);]!?\"")
        if not url.lower().startswith(("http://", "https://")):
            url = "https://" + url
        parsed = urlsplit(url)
        if parsed.hostname and not parsed.username and not parsed.password:
            vt_requested = bool(re.search(r"\b(?:virus\s*total|vt)\b", text, re.I))
            submit_requested = vt_requested and re.search(r"\b(submit|send|scan\s+this\s+url)\b", text, re.I)
            report_intent = "virustotal_submit_url" if submit_requested else "virustotal_url" if vt_requested and (parsed.path not in {"", "/"} or parsed.query) else "virustotal_domain" if vt_requested else "url"
            return {"intent": report_intent,
                    "url": url}
    if EMAIL_RE.search(text) and CHECK_RE.search(text):
        return {"intent": "email"}
    return {"intent": "unsupported"}
