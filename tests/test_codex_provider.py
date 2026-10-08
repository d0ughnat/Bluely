import json
import os
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from blueguard.config import Settings
from blueguard.models import _codex_environment, _codex_executable, chat_assistant, codex_status, explain


class CodexProviderTests(unittest.TestCase):
    @unittest.skipIf(os.name == "nt", "Linux user-service path test")
    def test_linux_user_install_is_found_without_shell_path(self):
        with tempfile.TemporaryDirectory() as directory:
            executable = Path(directory) / ".local/bin/codex"
            executable.parent.mkdir(parents=True)
            executable.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
            executable.chmod(0o700)
            with patch("blueguard.models.shutil.which", return_value=None), \
                 patch("blueguard.models.Path.home", return_value=Path(directory)):
                self.assertEqual(_codex_executable(), str(executable))
            environment = _codex_environment(str(executable))
            self.assertEqual(environment["PATH"].split(os.pathsep)[0], str(executable.parent))

    def test_subscription_login_is_required(self):
        with patch("blueguard.models._codex_executable", return_value="codex"), \
             patch("blueguard.models.subprocess.run", return_value=subprocess.CompletedProcess(
                 [], 0, "Logged in using API key", "")):
            self.assertFalse(codex_status()["connected"])

    def test_chat_uses_subscription_in_isolated_read_only_directory(self):
        settings = Settings(model_provider="codex", model_name="default")
        history = [{"role": "user", "content": "What should I check?"}]

        def fake_run(command, **kwargs):
            self.assertEqual(command[1], "exec")
            self.assertIn("--ephemeral", command)
            self.assertIn("shell_tool", command)
            self.assertIn("computer_use", command)
            self.assertEqual(command[command.index("--sandbox") + 1], "read-only")
            self.assertEqual(command[command.index("--output-schema") + 1],
                             str(Path(kwargs["cwd"]) / "reply-schema.json"))
            self.assertNotIn("--model", command)
            self.assertNotIn("OPENAI_API_KEY", kwargs["env"])
            self.assertIn("What should I check?", kwargs["input"])
            self.assertEqual(sorted(Path(kwargs["cwd"]).iterdir()),
                             [Path(kwargs["cwd"]) / "reply-schema.json"])
            Path(command[command.index("--output-last-message") + 1]).write_text(
                json.dumps({"reply": "Review recent alerts."}), encoding="utf-8")
            return subprocess.CompletedProcess(command, 0, "", "")

        with patch("blueguard.models.codex_status", return_value={"connected": True}), \
             patch("blueguard.models._codex_executable", return_value="codex"), \
             patch("blueguard.models.subprocess.run", side_effect=fake_run), \
             patch.dict(os.environ, {"OPENAI_API_KEY": "must-not-leak"}):
            reply, used = chat_assistant(settings, history)
        self.assertEqual(reply, "Review recent alerts.")
        self.assertEqual(used, "codex:default")

    def test_security_evidence_is_reduced_before_codex(self):
        settings = Settings(model_provider="codex", model_name="default")
        with patch("blueguard.models._codex_complete", return_value='{"reply":"Review this finding."}') as request:
            explanation, _ = explain(settings, "email", 60, "suspicious", [
                {"code": "auth_fail", "source": "headers", "detail": "secret email body"}],
                "private subject")
        self.assertEqual(explanation, "Review this finding.")
        payload = request.call_args.args[1]
        self.assertIn("auth_fail", payload)
        self.assertNotIn("secret email body", payload)
        self.assertNotIn("private subject", payload)


if __name__ == "__main__":
    unittest.main()
