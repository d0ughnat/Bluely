"""Check the packaged Windows agent and Chromium native host on the build runner."""

import json
import struct
import subprocess
import sys
import time
from pathlib import Path

from blueguard.windows_pipe import AGENT_PIPE, request


def main() -> None:
    root = Path(sys.argv[1]).resolve()
    agent_dir = root / ("bluely-agent" if (root / "bluely-agent").is_dir() else "agent")
    host_dir = root / ("bluely-native-host" if (root / "bluely-native-host").is_dir() else "native-host")
    flags = subprocess.CREATE_NO_WINDOW
    agent = subprocess.Popen([str(agent_dir / "bluely-agent.exe"), "service"], creationflags=flags)
    try:
        for _ in range(120):
            try:
                response = request(AGENT_PIPE, {"method": "status", "params": {}}, 250)
                break
            except OSError:
                if agent.poll() is not None:
                    raise RuntimeError(f"Packaged agent exited: {agent.returncode}")
                time.sleep(0.25)
        else:
            raise RuntimeError("Packaged agent did not open its named pipe")
        if agent.poll() is not None:
            raise RuntimeError(f"Packaged agent exited after opening its pipe: {agent.returncode}")
        assert response.get("ok") and "tools" in response["result"], response

        payload = json.dumps({"method": "status", "params": {}}).encode()
        framed = struct.pack("<I", len(payload)) + payload
        result = subprocess.run([str(host_dir / "bluely-native-host.exe")], input=framed,
                                capture_output=True, creationflags=flags, timeout=30, check=True)
        length = struct.unpack("<I", result.stdout[:4])[0]
        native = json.loads(result.stdout[4:4 + length])
        assert native.get("ok") and "tools" in native["result"], native
        print("Packaged Windows agent and native host smoke test passed")
    finally:
        agent.terminate()
        agent.wait(timeout=10)


if __name__ == "__main__":
    main()
