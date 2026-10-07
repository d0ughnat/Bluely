from __future__ import annotations

import json
import struct
import sys

from .service import request

ALLOWED = {"check_url", "scan_download", "status"}


def main() -> None:
    input_stream = sys.stdin.buffer
    output_stream = sys.stdout.buffer
    while length_bytes := input_stream.read(4):
        if len(length_bytes) != 4:
            return
        length = struct.unpack("<I", length_bytes)[0]
        if length > 1024 * 1024:
            return
        try:
            payload = json.loads(input_stream.read(length))
            method = payload.get("method", "")
            if method not in ALLOWED:
                raise ValueError("Method not available to Chrome")
            response = request(method, payload.get("params", {}))
        except Exception as error:
            response = {"ok": False, "error": str(error)[:200]}
        encoded = json.dumps(response).encode()
        output_stream.write(struct.pack("<I", len(encoded)) + encoded)
        output_stream.flush()
