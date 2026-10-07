from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class Decision:
    risk: int
    verdict: str
    quarantine_eligible: bool


def decide(evidence: list[dict]) -> Decision:
    score = 0
    strong = False
    for finding in evidence:
        code = finding.get("code")
        if code == "clamav_detected":
            score += 90
            strong = True
        elif code == "yara_high_confidence":
            score += 85
            strong = True
        elif code == "known_malicious_url":
            score += 85
        elif code == "vt_malicious_file":
            score += 65
        elif code == "vt_suspicious_file":
            score += 30
        elif code == "vt_malicious_domain":
            score += 60
        elif code == "vt_malicious_url":
            score += 60
        elif code == "yara_match":
            score += 35
        elif code == "reply_to_mismatch":
            score += 20
        elif code == "auth_fail":
            score += 20
        elif code == "display_link_mismatch":
            score += 25
        elif code == "credential_request":
            score += 15
        elif code == "suspicious_attachment":
            score += 20
    risk = min(100, score)
    verdict = "malicious" if risk >= 85 else "high" if risk >= 60 else "suspicious" if risk >= 30 else "low"
    return Decision(risk, verdict, strong)
