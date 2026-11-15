"""M093: adversarial slow-body and gzip-header tests, local-only loopback stub.

No actual ComfyUI, GPU, models, paid rental or external HTTP connections.
A body deadline does NOT guarantee a wall-clock bound on HTTP response headers.
"""
from __future__ import annotations

import gzip
import json
import os
import socketserver
import threading
import time
import unittest
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler
from unittest.mock import patch

import superfluid_safe_comfy as guard
from superfluid_safe_comfy import ReadonlyComfyUIClient, safe_check_comfyui_available


def inventory() -> bytes:
    return json.dumps({"CheckpointLoaderSimple": {
        "input": {"required": {"ckpt_name": [["synthetic.safetensors"]]}}
    }}).encode()


@contextmanager
def trickle_stub(body: bytes, *, interval: float = 0.018, encoding: str | None = None,
                 extra_headers: dict[str, str] | None = None):
    state = {"gets": [], "posts": []}
    class Stub(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.0"
        def do_GET(self):
            state["gets"].append(self.path)
            self.send_response(200)
            if encoding:
                self.send_header("Content-Encoding", encoding)
            for key, value in (extra_headers or {}).items():
                self.send_header(key, value)
            self.end_headers()
            for byte in body:
                try:
                    self.wfile.write(bytes([byte]))
                    self.wfile.flush()
                    time.sleep(interval)
                except (BrokenPipeError, ConnectionResetError):
                    break

        def do_POST(self):
            state["posts"].append(self.path)
            self.send_response(403)
            self.end_headers()

        def log_message(self, *_):
            pass

    class Backend(socketserver.ThreadingTCPServer):
        daemon_threads = True
        allow_reuse_address = True
    with Backend(("127.0.0.1", 0), Stub) as backend:
        t = threading.Thread(target=backend.serve_forever, daemon=True)
        t.start()
        try:
            yield f"http://127.0.0.1:{backend.server_address[1]}", state
        finally:
            backend.shutdown()
            t.join(timeout=4)


class DeadlineTests(unittest.TestCase):
    def test_plain_slow_trickle_body_expires_before_json_complete(self):
        with trickle_stub(inventory()) as (url, state):
            with patch.object(guard, "MAX_DISCOVERY_BODY_SECONDS", 0.1):
                started = time.monotonic()
                self.assertFalse(safe_check_comfyui_available(url))
                self.assertLess(time.monotonic() - started, 1.25)
            self.assertEqual(state["posts"], [])

    def test_model_list_slow_body_is_unavailable_not_authority(self):
        with trickle_stub(inventory()) as (url, state):
            with patch.object(guard, "MAX_DISCOVERY_BODY_SECONDS", 0.1):
                client = ReadonlyComfyUIClient(url)
            self.assertEqual(client.available_models, [])
            self.assertEqual(state["posts"], [])

    def test_gzip_optional_filename_header_cannot_hide_trickle(self):
        original = gzip.compress(inventory())
        # RFC1952 FLG FNAME: decoder has no payload to emit until NUL.
        crafted = original[:3] + b"\x08" + original[4:10] + b"metadata" * 80 + b"\x00" + original[10:]
        with trickle_stub(crafted, interval=0.012, encoding="gzip") as (url, state):
            with patch.object(guard, "MAX_DISCOVERY_BODY_SECONDS", 0.09):
                start = time.monotonic()
                self.assertFalse(safe_check_comfyui_available(url))
                self.assertLess(time.monotonic() - start, 1.25)
            self.assertEqual(state["posts"], [])

    def test_small_valid_gzip_remains_available(self):
        raw = gzip.compress(inventory())
        with trickle_stub(raw, interval=0.0, encoding="gzip") as (url, state):
            self.assertTrue(safe_check_comfyui_available(url))
            self.assertEqual(ReadonlyComfyUIClient(url).available_models,
                             ["synthetic.safetensors"])
            self.assertEqual(state["posts"], [])

    def test_unknown_content_encoding_denied_before_decode(self):
        with trickle_stub(inventory(), interval=0.0, encoding="br") as (url, state):
            self.assertFalse(safe_check_comfyui_available(url))
            self.assertEqual(ReadonlyComfyUIClient(url).available_models, [])
            self.assertEqual(state["posts"], [])

    def test_truncated_gzip_does_not_parse_partial_json(self):
        raw = gzip.compress(inventory())[:-6]
        with trickle_stub(raw, interval=0.0, encoding="gzip") as (url, _):
            self.assertFalse(safe_check_comfyui_available(url))
            self.assertEqual(ReadonlyComfyUIClient(url).available_models, [])

    def test_concatenated_gzip_member_denied(self):
        raw = gzip.compress(inventory()) + gzip.compress(inventory())
        with trickle_stub(raw, interval=0.0, encoding="gzip") as (url, _):
            self.assertFalse(safe_check_comfyui_available(url))
            self.assertEqual(ReadonlyComfyUIClient(url).available_models, [])

    def test_deadline_must_not_send_workflow_even_with_proxy_env(self):
        with trickle_stub(inventory()) as (url, state):
            with patch.object(guard, "MAX_DISCOVERY_BODY_SECONDS", 0.06):
                with patch.dict(os.environ, {
                    "HTTP_PROXY": "http://127.0.0.1:1",
                    "HTTPS_PROXY": "http://127.0.0.1:1",
                    "NO_PROXY": "",
                }):
                    self.assertFalse(safe_check_comfyui_available(url))
            self.assertEqual(state["posts"], [])
            self.assertEqual(state["gets"], ["/object_info/CheckpointLoaderSimple"])


if __name__ == "__main__":
    unittest.main()
