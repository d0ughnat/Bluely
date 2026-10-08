import tempfile
import threading
import time
import unittest
from concurrent.futures import Future, ThreadPoolExecutor
from pathlib import Path
from unittest.mock import patch

from blueguard.config import Settings
from blueguard.models import explain, summarize_event
from blueguard.service import Agent
from blueguard.storage import Store


class AlertExperienceTests(unittest.TestCase):
    def test_viewing_alerts_clears_badge_without_closing_findings(self):
        with tempfile.TemporaryDirectory() as temp:
            store = Store(Path(temp) / "alerts.sqlite3")
            try:
                with patch("blueguard.storage.now", return_value="2026-01-01T00:00:00+00:00"):
                    first = store.add_event("email", "first", 50, "suspicious", [])
                    self.assertEqual(store.unread_alert_count(), 1)
                    self.assertEqual(store.mark_alerts_seen(first["created_at"]), 0)
                    self.assertEqual(store.get_event(first["id"])["status"], "open")
                    self.assertEqual(store.unread_alert_count(), 0)
                    second = store.add_event("email", "second", 60, "suspicious", [])
                    self.assertGreater(second["created_at"], first["created_at"])
                    self.assertEqual(store.unread_alert_count(), 1)
                    self.assertEqual(store.mark_alerts_seen(second["created_at"]), 0)
            finally:
                store.close()
            reopened = Store(Path(temp) / "alerts.sqlite3")
            self.assertEqual(reopened.unread_alert_count(), 0)
            reopened.close()

    def test_bad_model_output_uses_readable_policy_summary(self):
        settings = Settings(model_provider="ollama", model_name="qwen3:4b")
        evidence = [{"source": "headers", "code": "reply_to_mismatch", "detail": "private"}]
        with patch("blueguard.models.request_json", return_value={"message": {"content": "{}"}}):
            summary, source = summarize_event(settings, "email", 40, "suspicious", evidence, "private subject")
        self.assertEqual(source, "policy:fallback")
        self.assertIn("reply address differs", summary)
        self.assertNotIn("{}", summary)
        self.assertNotIn("private", summary)

    def test_valid_structured_alert_summary_is_plain_text(self):
        settings = Settings(model_provider="ollama", model_name="qwen3:4b")
        with patch("blueguard.models.request_json", return_value={"message": {"content": '{"reply":"The sender and reply address differ. Review the message before acting."}'}}):
            summary, source = explain(settings, "email", 40, "suspicious", [])
        self.assertEqual(summary, "The sender and reply address differ. Review the message before acting.")
        self.assertEqual(source, "ollama:qwen3:4b")

    def test_existing_explanations_are_repaired_once(self):
        with tempfile.TemporaryDirectory() as temp:
            store = Store(Path(temp) / "alerts.sqlite3")
            event = store.add_event("email", "old", 40, "suspicious", [], explanation="{}")
            agent = Agent.__new__(Agent)
            agent.store = store
            agent.settings = Settings()
            with patch("blueguard.service.summarize_event", return_value=("Readable summary.", "policy:fallback")):
                agent._repair_alert_summaries()
            self.assertEqual(store.get_event(event["id"])["explanation"], "Readable summary.")
            self.assertEqual(store.get_state("alert_summary_version"), "2")
            store.close()

    def test_scan_result_selects_highest_risk_finding_and_links_its_id(self):
        with tempfile.TemporaryDirectory() as temp:
            store = Store(Path(temp) / "alerts.sqlite3")
            low = store.add_event("email", "lower risk", 35, "suspicious", [])
            high = store.add_event("email", "highest risk", 90, "malicious", [], explanation="Threat-list match.")
            future = Future()
            future.set_result({"status": "completed", "kind": "email", "messages": 5,
                               "finding_ids": [low["id"], high["id"]]})
            agent = Agent.__new__(Agent)
            agent.store = store
            agent._scan_job_lock = threading.Lock()
            agent._scan_jobs = {"scan-1": (time.monotonic(), future)}
            result = agent.dispatch("assistant_scan_result", {"scan_id": "scan-1"})
            self.assertEqual(result["messages"], 5)
            self.assertEqual(result["findings"], 2)
            self.assertEqual(result["top_finding"]["id"], high["id"])
            self.assertEqual(result["top_finding"]["summary"], "Threat-list match.")
            store.close()

    def test_scan_result_reports_zero_findings(self):
        future = Future()
        future.set_result({"status": "completed", "kind": "email", "messages": 3, "finding_ids": []})
        agent = Agent.__new__(Agent)
        agent._scan_job_lock = threading.Lock()
        agent._scan_jobs = {"scan-2": (time.monotonic(), future)}
        agent.store = None
        result = agent.dispatch("assistant_scan_result", {"scan_id": "scan-2"})
        self.assertEqual(result["findings"], 0)
        self.assertIsNone(result["top_finding"])

    def test_assistant_email_request_updates_with_completed_scan_result(self):
        with tempfile.TemporaryDirectory() as temp:
            store = Store(Path(temp) / "alerts.sqlite3")
            finding = store.add_event("email", "priority finding", 85, "malicious", [])

            class FakeGmail:
                def status(self):
                    return {"connected": True}

                def scan(self, _explain):
                    return {"status": "completed", "messages": 2, "alerts": 1,
                            "finding_ids": [finding["id"]], "truncated": False}

            agent = Agent.__new__(Agent)
            agent.gmail = FakeGmail()
            agent.store = store
            agent._explain = lambda _event: None
            agent._gmail_lock = threading.Lock()
            agent._scan_job_lock = threading.Lock()
            agent._scan_jobs = {}
            agent._scan_paths = {}
            agent._scan_pool = ThreadPoolExecutor(max_workers=1)
            try:
                started = agent.dispatch("assistant_request", {"message": "check my email"})
                self.assertEqual(started["status"], "started")
                self.assertIn("scan_id", started)
                result = agent.dispatch("assistant_scan_result", {"scan_id": started["scan_id"]})
                if result["status"] == "pending":
                    time.sleep(0.02)
                    result = agent.dispatch("assistant_scan_result", {"scan_id": started["scan_id"]})
                self.assertEqual(result["status"], "completed")
                self.assertEqual(result["top_finding"]["id"], finding["id"])
            finally:
                agent._scan_pool.shutdown(wait=True)
                store.close()


if __name__ == "__main__":
    unittest.main()
