from __future__ import annotations

import json
import sqlite3
import threading
from datetime import datetime, timedelta, timezone
from pathlib import Path
from uuid import uuid4

from .config import DATA_DIR


def now() -> str:
    return datetime.now(timezone.utc).isoformat()


class Store:
    def __init__(self, path: Path | None = None):
        self.path = path or DATA_DIR / "blueguard.sqlite3"
        self.path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        self._lock = threading.RLock()
        self.db = sqlite3.connect(self.path, check_same_thread=False)
        self.db.row_factory = sqlite3.Row
        self.db.executescript("""
            PRAGMA journal_mode=WAL;
            CREATE TABLE IF NOT EXISTS events (
                id TEXT PRIMARY KEY,
                created_at TEXT NOT NULL,
                kind TEXT NOT NULL,
                subject TEXT NOT NULL,
                risk INTEGER NOT NULL,
                verdict TEXT NOT NULL,
                evidence TEXT NOT NULL,
                explanation TEXT NOT NULL DEFAULT '',
                model_used TEXT NOT NULL DEFAULT '',
                status TEXT NOT NULL DEFAULT 'open',
                source_key TEXT UNIQUE
            );
            CREATE TABLE IF NOT EXISTS audit (
                id TEXT PRIMARY KEY,
                created_at TEXT NOT NULL,
                event_id TEXT,
                action TEXT NOT NULL,
                authorization TEXT NOT NULL,
                result TEXT NOT NULL,
                detail TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS quarantine (
                id TEXT PRIMARY KEY,
                event_id TEXT NOT NULL,
                original_path TEXT NOT NULL,
                stored_path TEXT NOT NULL,
                sha256 TEXT NOT NULL,
                created_at TEXT NOT NULL,
                restored_at TEXT
            );
            CREATE TABLE IF NOT EXISTS state (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS processed_messages (
                id TEXT PRIMARY KEY,
                processed_at TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS events_created_at ON events(created_at DESC);
        """)
        self.db.commit()
        try:
            self.path.chmod(0o600)
        except OSError:
            pass

    def close(self) -> None:
        with self._lock:
            self.db.close()

    def add_event(self, kind: str, subject: str, risk: int, verdict: str,
                  evidence: list[dict], *, source_key: str | None = None,
                  explanation: str = "", model_used: str = "") -> dict:
        event_id = str(uuid4())
        with self._lock:
            created_at = now()
            latest = self.db.execute("SELECT MAX(created_at) FROM events").fetchone()[0]
            if latest and created_at <= latest:
                created_at = (datetime.fromisoformat(latest) + timedelta(microseconds=1)).isoformat()
            self.db.execute("""INSERT OR IGNORE INTO events
                (id, created_at, kind, subject, risk, verdict, evidence,
                 explanation, model_used, source_key) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (event_id, created_at, kind, subject[:300], risk, verdict,
                 json.dumps(evidence), explanation[:2000], model_used, source_key))
            self.db.commit()
            if source_key:
                row = self.db.execute("SELECT * FROM events WHERE source_key = ?", (source_key,)).fetchone()
            else:
                row = self.db.execute("SELECT * FROM events WHERE id = ?", (event_id,)).fetchone()
        return self._event(row)

    def update_explanation(self, event_id: str, explanation: str, model_used: str) -> None:
        with self._lock:
            self.db.execute("UPDATE events SET explanation = ?, model_used = ? WHERE id = ?",
                            (explanation[:2000], model_used, event_id))
            self.db.commit()

    def get_event(self, event_id: str) -> dict | None:
        with self._lock:
            row = self.db.execute("SELECT * FROM events WHERE id = ?", (event_id,)).fetchone()
        return self._event(row) if row else None

    def list_events(self, limit: int = 100) -> list[dict]:
        with self._lock:
            rows = self.db.execute("SELECT * FROM events ORDER BY created_at DESC LIMIT ?",
                                   (min(max(limit, 1), 500),)).fetchall()
        return [self._event(row) for row in rows]

    def list_all_events(self) -> list[dict]:
        with self._lock:
            rows = self.db.execute("SELECT * FROM events ORDER BY created_at DESC").fetchall()
        return [self._event(row) for row in rows]

    def unread_alert_count(self) -> int:
        seen_through = self.get_state("alerts_seen_through") or ""
        with self._lock:
            if seen_through:
                row = self.db.execute("SELECT COUNT(*) FROM events WHERE risk >= 30 AND status = 'open' "
                                      "AND created_at > ?", (seen_through,)).fetchone()
            else:
                row = self.db.execute("SELECT COUNT(*) FROM events WHERE risk >= 30 AND status = 'open'").fetchone()
        return int(row[0])

    def mark_alerts_seen(self, through: str) -> int:
        with self._lock:
            if not self.db.execute("SELECT 1 FROM events WHERE created_at = ?", (through,)).fetchone():
                raise ValueError("Unknown alert checkpoint")
            previous = self.get_state("alerts_seen_through") or ""
            if through > previous:
                self.set_state("alerts_seen_through", through)
        return self.unread_alert_count()

    def audit(self, action: str, authorization: str, result: str,
              detail: dict, event_id: str | None = None) -> None:
        with self._lock:
            self.db.execute("INSERT INTO audit VALUES (?, ?, ?, ?, ?, ?, ?)",
                            (str(uuid4()), now(), event_id, action, authorization,
                             result, json.dumps(detail)))
            self.db.commit()

    def list_audit(self, limit: int = 100) -> list[dict]:
        with self._lock:
            rows = self.db.execute("SELECT * FROM audit ORDER BY created_at DESC LIMIT ?",
                                   (min(max(limit, 1), 500),)).fetchall()
        return [{**dict(row), "detail": json.loads(row["detail"])} for row in rows]

    def add_quarantine(self, event_id: str, original_path: str,
                       stored_path: str, sha256: str) -> dict:
        record = {"id": str(uuid4()), "event_id": event_id,
                  "original_path": original_path, "stored_path": stored_path,
                  "sha256": sha256, "created_at": now(), "restored_at": None}
        with self._lock:
            self.db.execute("INSERT INTO quarantine VALUES (?, ?, ?, ?, ?, ?, ?)", tuple(record.values()))
            self.db.execute("UPDATE events SET status = 'quarantined' WHERE id = ?", (event_id,))
            self.db.commit()
        return record

    def get_quarantine(self, record_id: str) -> dict | None:
        with self._lock:
            row = self.db.execute("SELECT * FROM quarantine WHERE id = ?", (record_id,)).fetchone()
        return dict(row) if row else None

    def list_quarantine(self) -> list[dict]:
        with self._lock:
            rows = self.db.execute("SELECT * FROM quarantine ORDER BY created_at DESC").fetchall()
        return [dict(row) for row in rows]

    def mark_restored(self, record_id: str) -> None:
        with self._lock:
            row = self.db.execute("SELECT event_id FROM quarantine WHERE id = ?", (record_id,)).fetchone()
            self.db.execute("UPDATE quarantine SET restored_at = ? WHERE id = ?", (now(), record_id))
            if row:
                self.db.execute("UPDATE events SET status = 'restored' WHERE id = ?", (row["event_id"],))
            self.db.commit()

    def get_state(self, key: str) -> str | None:
        with self._lock:
            row = self.db.execute("SELECT value FROM state WHERE key = ?", (key,)).fetchone()
        return row["value"] if row else None

    def set_state(self, key: str, value: str) -> None:
        with self._lock:
            self.db.execute("INSERT INTO state(key, value) VALUES(?, ?) "
                            "ON CONFLICT(key) DO UPDATE SET value = excluded.value", (key, value))
            self.db.commit()

    def is_message_processed(self, message_id: str) -> bool:
        with self._lock:
            row = self.db.execute("SELECT 1 FROM processed_messages WHERE id = ?", (message_id,)).fetchone()
        return row is not None

    def mark_message_processed(self, message_id: str) -> None:
        with self._lock:
            self.db.execute("INSERT OR IGNORE INTO processed_messages VALUES (?, ?)",
                            (message_id, now()))
            self.db.commit()

    def reset_gmail_scan(self) -> None:
        with self._lock:
            self.db.execute("DELETE FROM state WHERE key = 'gmail_last_scan'")
            self.db.execute("DELETE FROM processed_messages")
            self.db.commit()

    @staticmethod
    def _event(row: sqlite3.Row) -> dict:
        return {**dict(row), "evidence": json.loads(row["evidence"])}
