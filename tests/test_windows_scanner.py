import errno
import tempfile
import unittest
from subprocess import CompletedProcess
from pathlib import Path
from unittest.mock import patch

from blueguard.config import Settings
from blueguard.defender_broker import _validated_snapshot, scan
from blueguard.policy import decide
from blueguard.scanners import scan_file
from blueguard.service import _move_verified


class WindowsScannerTests(unittest.TestCase):
    def test_cross_volume_quarantine_copy_is_verified(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "source.bin"
            destination = root / "quarantine.bin"
            source.write_bytes(b"fixture")
            import hashlib
            digest = hashlib.sha256(b"fixture").hexdigest()
            with patch("blueguard.service.os.rename", side_effect=OSError(errno.EXDEV, "other volume")):
                _move_verified(source, destination, digest)
            self.assertFalse(source.exists())
            self.assertEqual(destination.read_bytes(), b"fixture")

    def test_defender_detection_allows_confirmed_quarantine(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            download = root / "sample.txt"
            download.write_bytes(b"harmless fixture")
            with patch("blueguard.scanners.sys.platform", "win32"), \
                 patch("blueguard.scanners.DATA_DIR", root / "data"), \
                 patch("blueguard.scanners.allowed_download", return_value=download), \
                 patch("blueguard.scanners.shutil.which", return_value=None), \
                 patch("blueguard.windows_pipe.request", return_value={"status": "detected"}):
                result = scan_file(str(download), Settings(downloads_dir=str(root)))
        self.assertEqual(result["tools"]["defender"], "detected")
        self.assertTrue(decide(result["evidence"]).quarantine_eligible)

    def test_broker_rejects_snapshots_outside_caller_scan_folder(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            scan_root = root / "AppData/Local/Bluely/scan"
            snapshot = scan_root / "scan-1/sample.bin"
            snapshot.parent.mkdir(parents=True)
            snapshot.write_bytes(b"fixture")
            self.assertEqual(_validated_snapshot(str(snapshot), scan_root), snapshot.resolve())
            outside = root / "other.bin"
            outside.write_bytes(b"fixture")
            with self.assertRaisesRegex(ValueError, "outside"):
                _validated_snapshot(str(outside), scan_root)

    def test_defender_result_requires_explicit_detection(self):
        with tempfile.TemporaryDirectory() as directory:
            snapshot = Path(directory) / "sample.bin"
            snapshot.write_bytes(b"fixture")
            import hashlib
            digest = hashlib.sha256(b"fixture").hexdigest()
            with patch("blueguard.defender_broker.defender_executable", return_value=Path("MpCmdRun.exe")), \
                 patch("blueguard.defender_broker.subprocess.run", return_value=CompletedProcess(
                     [], 2, stdout="Threat found", stderr="")):
                self.assertEqual(scan(snapshot, digest)["status"], "detected")
            with patch("blueguard.defender_broker.defender_executable", return_value=Path("MpCmdRun.exe")), \
                 patch("blueguard.defender_broker.subprocess.run", return_value=CompletedProcess(
                     [], 2, stdout="Scan failed", stderr="")):
                self.assertEqual(scan(snapshot, digest)["status"], "error")
            with patch("blueguard.defender_broker.defender_executable", return_value=Path("MpCmdRun.exe")), \
                 patch("blueguard.defender_broker.subprocess.run", return_value=CompletedProcess(
                     [], 0, stdout="No threats found", stderr="")):
                self.assertEqual(scan(snapshot, digest)["status"], "clean")
