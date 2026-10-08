import io
import tempfile
import time
import unittest
from pathlib import Path
from urllib.error import HTTPError
from urllib.parse import parse_qs, urlsplit
from urllib.request import urlopen
from unittest.mock import patch

from blueguard.config import Settings
from blueguard.email_guard import Gmail
from blueguard.http_client import RemoteError
from blueguard.storage import Store


class FakeStore:
    def __init__(self):
        self.entries = []

    def get_state(self, _key):
        return None

    def audit(self, *args):
        self.entries.append(args)

    def reset_gmail_scan(self):
        self.entries.append(("reset_gmail_scan",))


class GmailOAuthTests(unittest.TestCase):
    def test_missing_client_secret_fails_before_browser_authorization(self):
        gmail = Gmail(Settings(gmail_client_id="desktop-client.apps.googleusercontent.com"), FakeStore(), None)
        with patch("blueguard.email_guard.secrets.get", return_value=""):
            with self.assertRaisesRegex(ValueError, "client secret in Integrations"):
                gmail.connect()
        self.assertEqual(gmail._oauth_status, "idle")

    def test_browser_callback_exchanges_code_and_stores_refresh_token(self):
        store = FakeStore()
        gmail = Gmail(Settings(gmail_client_id="desktop-client.apps.googleusercontent.com"), store, None)
        saved = {}
        with patch("blueguard.email_guard.secrets.get", return_value="desktop-secret"), \
             patch("blueguard.email_guard.secrets.set_secret", side_effect=lambda name, value: saved.update({name: value})), \
             patch.object(gmail, "_token_request", return_value={"access_token": "access", "refresh_token": "refresh", "expires_in": 3600}) as token:
            result = gmail.connect()
            self.assertEqual(result["status"], "waiting")
            self.assertEqual(gmail.connect()["authorization_url"], result["authorization_url"])
            query = parse_qs(urlsplit(result["authorization_url"]).query)
            self.assertEqual(query["code_challenge_method"], ["S256"])
            callback = query["redirect_uri"][0] + "?state=" + query["state"][0] + "&code=auth-code"
            with urlopen(callback, timeout=3) as response:
                self.assertIn(b"Return to Bluely", response.read())
            for _ in range(100):
                if gmail._oauth_status != "waiting":
                    break
                time.sleep(0.01)
            self.assertEqual(gmail._oauth_status, "connected")
            self.assertEqual(saved["gmail_refresh_token"], "refresh")
            self.assertEqual(token.call_args.args[0]["code"], "auth-code")
            self.assertEqual(token.call_args.args[0]["client_secret"], "desktop-secret")
            self.assertEqual(token.call_args.args[0]["redirect_uri"], query["redirect_uri"][0])

    def test_google_token_error_code_is_visible_without_response_body(self):
        body = io.BytesIO(b'{"error":"invalid_client","error_description":"private details"}')
        error = HTTPError("https://oauth2.googleapis.com/token", 401, "Unauthorized", {}, body)
        with patch("blueguard.email_guard.urlopen", side_effect=error):
            with self.assertRaisesRegex(RemoteError, r"invalid_client \(HTTP 401\)") as raised:
                Gmail._token_request({"client_id": "test"})
        self.assertNotIn("private details", str(raised.exception))

    def test_sign_out_clears_local_token_and_scan_checkpoint(self):
        store = FakeStore()
        gmail = Gmail(Settings(gmail_client_id="desktop-client.apps.googleusercontent.com"), store, None)
        gmail._access_token = "cached-access"
        gmail._expires_at = time.monotonic() + 3600
        gmail._oauth_status = "connected"
        with patch("blueguard.email_guard.secrets.set_secret") as set_secret, \
             patch("blueguard.email_guard.secrets.get", return_value=""):
            self.assertEqual(gmail.disconnect(), {"status": "signed_out"})
            set_secret.assert_called_once_with("gmail_refresh_token", "")
            with self.assertRaisesRegex(ValueError, "not connected"):
                gmail._token()
        self.assertEqual(gmail._access_token, "")
        self.assertEqual(gmail._oauth_status, "idle")
        self.assertIn(("reset_gmail_scan",), store.entries)

    def test_sign_out_stops_an_active_scan_before_processing_messages(self):
        gmail = Gmail(Settings(), FakeStore(), None)

        def first_page(_path, _params):
            gmail.disconnect()
            return {"messages": [{"id": "should-not-process"}]}

        with patch.object(gmail, "_get", side_effect=first_page), \
             patch("blueguard.email_guard.secrets.set_secret"):
            result = gmail.scan()
        self.assertEqual(result["status"], "cancelled")
        self.assertEqual(result["messages"], 0)

    def test_scan_returns_ids_of_findings_created_in_this_run(self):
        with tempfile.TemporaryDirectory() as temp:
            store = Store(Path(temp) / "gmail.sqlite3")
            gmail = Gmail(Settings(), store, None)

            def gmail_response(path, _params):
                if path == "/messages":
                    return {"messages": [{"id": "message-1"}]}
                return {"id": "message-1", "internalDate": str(int(time.time() * 1000))}

            finding = {"subject": "test", "sender_domain": "example.com",
                       "evidence": [{"source": "safe_browsing", "code": "known_malicious_url"}]}
            with patch.object(gmail, "_get", side_effect=gmail_response), \
                 patch("blueguard.email_guard.inspect_message", return_value=finding):
                result = gmail.scan()
            self.assertEqual(result["status"], "completed")
            self.assertEqual(result["alerts"], 1)
            self.assertEqual(len(result["finding_ids"]), 1)
            self.assertEqual(store.get_event(result["finding_ids"][0])["risk"], 85)
            store.close()


if __name__ == "__main__":
    unittest.main()
