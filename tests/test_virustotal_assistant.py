import io
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
from urllib.error import HTTPError

from blueguard.assistant import parse_request
from blueguard.config import Settings
from blueguard.models import chat_assistant
from blueguard.policy import decide
from blueguard.service import Agent
from blueguard.virustotal import VirusTotal, public_domain


class VirusTotalTests(unittest.TestCase):
    def test_url_lookup_requires_consent_and_encodes_full_url(self):
        url = "https://example.com/path?item=1"
        vt = VirusTotal()
        with self.assertRaises(ValueError):
            vt.lookup_url(url)
        calls = []

        def fake_open(request, timeout):
            calls.append(request.full_url)
            return io.BytesIO(json.dumps({"data": {"attributes": {"last_analysis_stats": {"harmless": 2}}}}).encode())

        with patch("blueguard.virustotal.secrets.get", return_value="test-key"), \
             patch("blueguard.virustotal.urlopen", side_effect=fake_open):
            result = vt.lookup_url(url, True)
        self.assertEqual(result["id"], "example.com")
        self.assertEqual(result["status"], "no_match")
        self.assertNotIn("item=1", calls[0])
        self.assertIn("/urls/", calls[0])

    def test_ip_lookup_rejects_private_address(self):
        vt = VirusTotal()
        with self.assertRaises(ValueError):
            vt.lookup_ip("192.168.1.1")
        calls = []

        def fake_open(request, timeout):
            calls.append(request.full_url)
            return io.BytesIO(json.dumps({"data": {"attributes": {"last_analysis_stats": {"malicious": 5}}}}).encode())

        with patch("blueguard.virustotal.secrets.get", return_value="test-key"), \
             patch("blueguard.virustotal.urlopen", side_effect=fake_open):
            self.assertEqual(vt.lookup_ip("8.8.8.8")["status"], "malicious")
        self.assertEqual(calls, ["https://www.virustotal.com/api/v3/ip_addresses/8.8.8.8"])

    def test_url_submission_and_analysis(self):
        vt = VirusTotal()
        with self.assertRaises(ValueError):
            vt.submit_url("https://example.com/private")
        calls = []

        def fake_open(request, timeout):
            calls.append(request)
            data = ({"data": {"id": "abc12345"}} if request.get_method() == "POST" else
                    {"data": {"attributes": {"status": "completed", "stats": {"malicious": 2}}}})
            return io.BytesIO(json.dumps(data).encode())

        with patch("blueguard.virustotal.secrets.get", return_value="test-key"), \
             patch("blueguard.virustotal.urlopen", side_effect=fake_open):
            submitted = vt.submit_url("https://example.com/private", True)
            analysis = vt.analysis(submitted["analysis_id"])
        self.assertEqual(submitted["status"], "queued")
        self.assertEqual(analysis["malicious"], 2)
        self.assertEqual(calls[0].data, b"url=https%3A%2F%2Fexample.com%2Fprivate")
        self.assertEqual(calls[1].get_method(), "GET")

    def test_upload_needs_consent_and_uses_generic_filename(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "personal-name.txt"
            path.write_bytes(b"sample")
            vt = VirusTotal()
            with self.assertRaises(ValueError):
                vt.upload_file(str(path))
            calls = []

            def fake_open(request, timeout):
                calls.append(request)
                return io.BytesIO(json.dumps({"data": {"id": "abc12345"}}).encode())

            with patch("blueguard.virustotal.secrets.get", return_value="test-key"), \
                 patch("blueguard.virustotal.urlopen", side_effect=fake_open):
                result = vt.upload_file(str(path), True)
            self.assertEqual(result["status"], "queued")
            self.assertIn(b"sample", calls[0].data)
            self.assertIn(b"filename=\"sample.bin\"", calls[0].data)
            self.assertNotIn(b"personal-name", calls[0].data)

    def test_file_lookup_sends_only_hash_and_never_uploads_bytes(self):
        calls = []
        digest = "a" * 64

        def fake_open(request, timeout):
            calls.append((request.full_url, request.get_method(), request.data, timeout))
            return io.BytesIO(json.dumps({"data": {"attributes": {"last_analysis_stats": {
                "malicious": 8, "suspicious": 1, "harmless": 40, "undetected": 10}}}}).encode())

        with patch("blueguard.virustotal.secrets.get", return_value="test-key"), \
             patch("blueguard.virustotal.urlopen", side_effect=fake_open):
            vt = VirusTotal()
            first = vt.lookup_file(digest)
            second = vt.lookup_file(digest)
        self.assertEqual(first["status"], "malicious")
        self.assertEqual(second, first)
        self.assertEqual(calls, [(f"https://www.virustotal.com/api/v3/files/{digest}", "GET", None, 12)])
        self.assertFalse(decide([{"source": "virustotal", "code": "vt_malicious_file"}]).quarantine_eligible)

    def test_private_domain_and_full_url_are_not_sent(self):
        self.assertEqual(public_domain("https://example.com/private?token=secret"), "example.com")
        for url in ("http://localhost/", "https://server.internal/path", "https://127.0.0.1/",
                    "https://user:pass@example.com/"):
            with self.subTest(url=url), self.assertRaises(ValueError):
                public_domain(url)
        calls = []

        def fake_open(request, timeout):
            calls.append(request.full_url)
            return io.BytesIO(json.dumps({"data": {"attributes": {"last_analysis_stats": {"harmless": 1}}}}).encode())

        with patch("blueguard.virustotal.secrets.get", return_value="test-key"), \
             patch("blueguard.virustotal.urlopen", side_effect=fake_open):
            self.assertEqual(VirusTotal().lookup_domain("https://example.com/private?token=secret")["status"], "no_match")
        self.assertEqual(calls, ["https://www.virustotal.com/api/v3/domains/example.com"])

    def test_not_found_and_local_rate_limit_are_distinct_from_safe(self):
        with patch("blueguard.virustotal.secrets.get", return_value="test-key"), \
             patch("blueguard.virustotal.urlopen", side_effect=HTTPError("url", 404, "", {}, None)):
            self.assertEqual(VirusTotal().lookup_file("b" * 64)["status"], "not_found")

        def fake_open(request, timeout):
            return io.BytesIO(json.dumps({"data": {"attributes": {"last_analysis_stats": {"harmless": 1}}}}).encode())

        with patch("blueguard.virustotal.secrets.get", return_value="test-key"), \
             patch("blueguard.virustotal.urlopen", side_effect=fake_open) as remote:
            vt = VirusTotal()
            for digit in "1234":
                self.assertEqual(vt.lookup_file(digit * 64)["status"], "no_match")
            self.assertEqual(vt.lookup_file("5" * 64)["status"], "rate_limited")
            self.assertEqual(remote.call_count, 4)


class AssistantTests(unittest.TestCase):
    def test_investigation_reply_requires_further_action(self):
        settings = Settings()
        settings.model_provider = "ollama"
        settings.model_name = "test-model"
        settings.model_endpoint = "http://127.0.0.1:11434"
        payload = {"status": "malicious", "kind": "files", "malicious": 8}
        with patch("blueguard.models.request_json", return_value={"message": {"content": '{"reply":"Finding summary only."}'}}):
            with self.assertRaises(Exception):
                from blueguard.models import draft_assistant_note
                draft_assistant_note(settings, "virustotal_file", "malicious", payload)

    def test_local_model_receives_thread_and_cloud_general_chat_stays_local(self):
        settings = Settings()
        settings.model_provider = "ollama"
        settings.model_name = "test-model"
        settings.model_endpoint = "http://127.0.0.1:11434"
        history = [{"role": "user", "content": "What should I check?"},
                   {"role": "assistant", "content": "Start with your email."},
                   {"role": "user", "content": "And then?"}]
        with patch("blueguard.models.request_json", return_value={"message": {"content": '{"reply":"Check recent downloads next."}'}}) as remote:
            reply, model = chat_assistant(settings, history)
        self.assertEqual(reply, "Check recent downloads next.")
        self.assertEqual(model, "ollama:test-model")
        self.assertIn("And then?", remote.call_args.kwargs["body"]["messages"][1]["content"])
        settings.model_provider = "openai"
        with self.assertRaises(ValueError), patch("blueguard.models.request_json") as remote:
            chat_assistant(settings, history)
        remote.assert_not_called()

    def test_supported_requests_are_deterministic(self):
        self.assertEqual(parse_request("Can you check my email?")["intent"], "email")
        self.assertEqual(parse_request("is https://example.com/path safe?")["url"],
                         "https://example.com/path")
        self.assertEqual(parse_request("check example.com with VirusTotal")["intent"],
                         "virustotal_domain")
        self.assertEqual(parse_request("check https://example.com/login?next=1 with VirusTotal")["intent"],
                         "virustotal_url")
        self.assertEqual(parse_request("submit this URL to VirusTotal: https://example.com/login")["intent"],
                         "virustotal_submit_url")
        self.assertEqual(parse_request("upload /home/user/Downloads/sample.zip to VirusTotal")["intent"],
                         "virustotal_upload_file")
        self.assertEqual(parse_request("check VirusTotal analysis abc12345")["intent"],
                         "virustotal_analysis")
        self.assertEqual(parse_request("delete everything")["intent"], "unsupported")

    def test_chat_does_not_call_model_or_claim_no_match_is_safe(self):
        agent = Agent.__new__(Agent)

        class FakeReputation:
            def check(self, url):
                return {"status": "no_match", "host": "example.com", "threats": []}

        agent.reputation = FakeReputation()
        agent._queue_assistant_reply = lambda result: result
        result = agent.dispatch("assistant_request", {"message": "check https://example.com if safe"})
        self.assertEqual(result["status"], "no_match")
        self.assertIn("does not prove", result["message"])

    def test_url_request_merges_safe_browsing_and_virustotal(self):
        agent = Agent.__new__(Agent)

        class FakeReputation:
            def check(self, url):
                return {"status": "no_match", "host": "example.com", "threats": []}

        class FakeVirusTotal:
            def lookup_url(self, url, confirmed=False):
                self.called = (url, confirmed)
                return {"status": "suspicious", "id": "example.com", "malicious": 1, "suspicious": 3,
                        "harmless": 20, "undetected": 40}

        agent.reputation = FakeReputation()
        agent.virustotal = FakeVirusTotal()
        agent._queue_assistant_reply = lambda result: result
        result = agent.dispatch("assistant_request", {"message": "check https://example.com/login"})
        self.assertEqual(result["status"], "suspicious")
        self.assertIn("Safe Browsing returned no match", result["message"])
        self.assertIn("VirusTotal returned suspicious", result["message"])
        self.assertEqual(agent.virustotal.called, ("https://example.com/login", True))


if __name__ == "__main__":
    unittest.main()
