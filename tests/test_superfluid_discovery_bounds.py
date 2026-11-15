"""M092 synthetic adversarial tests of bounded ComfyUI discovery.

Only ephemeral 127.0.0.1 HTTP stub, never a GPU host or real ComfyUI.
"""
from __future__ import annotations

import gzip
import json
import os
import socketserver
import threading
import unittest
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler
from unittest.mock import patch

from superfluid_safe_comfy import (
    MAX_DISCOVERY_BYTES, ReadonlyComfyUIClient, safe_check_comfyui_available
)


def make_payload(*, extra: int = 0) -> bytes:
    return json.dumps({
        "CheckpointLoaderSimple": {
            "input": {"required": {"ckpt_name": [["synthetic.safetensors"]]}},
            "padding": "Z" * extra,
        }
    }, separators=(",", ":")).encode()


@contextmanager
def stub_server(body: bytes, headers: dict[str, str] | None = None,
                status: int = 200):
    state = {"gets": [], "posts": [], "sent": 0}
    headers = headers or {}

    class Stub(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.0"
        def do_GET(self):
            state["gets"].append(self.path)
            self.send_response(status)
            for key, val in headers.items():
                self.send_header(key, val)
            self.end_headers()
            try:
                self.wfile.write(body)
                state["sent"] += len(body)
            except (BrokenPipeError, ConnectionResetError):
                pass

        def do_POST(self):
            state["posts"].append(self.path)
            self.send_response(403)
            self.end_headers()

        def log_message(self, *_):
            pass

    class Backend(socketserver.ThreadingTCPServer):
        allow_reuse_address = True
        daemon_threads = True

    with Backend(("127.0.0.1", 0), Stub) as backend:
        t = threading.Thread(target=backend.serve_forever, daemon=True)
        t.start()
        try:
            yield f"http://127.0.0.1:{backend.server_address[1]}", state
        finally:
            backend.shutdown()
            t.join(timeout=4)


class DiscoveryBoundsTests(unittest.TestCase):
    def assert_rejected(self, payload, headers=None, status=200):
        with stub_server(payload, headers, status) as (url, state):
            with patch.dict(os.environ, {
                "HTTP_PROXY": "http://127.0.0.1:1",
                "HTTPS_PROXY": "http://127.0.0.1:1",
                "NO_PROXY": "",
            }):
                self.assertFalse(safe_check_comfyui_available(url))
                self.assertIsNone(ReadonlyComfyUIClient(url).available_models)
            self.assertEqual(state["posts"], [])
            self.assertEqual(state["gets"], ["/object_info/CheckpointLoaderSimple"] * 2)

    def test_clean_valid_small_response_preserves_discovery(self):
        with stub_server(make_payload()) as (url, state):
            self.assertTrue(safe_check_comfyui_available(url))
            self.assertEqual(ReadonlyComfyUIClient(url).available_models,
                             ["synthetic.safetensors"])
            self.assertEqual(state["posts"], [])

    def test_maximum_decoded_response_exactly_allowed(self):
        base = make_payload()
        exact = base + b" " * (MAX_DISCOVERY_BYTES - len(base))
        self.assertEqual(len(exact), MAX_DISCOVERY_BYTES)
        with stub_server(exact) as (url, _):
            self.assertTrue(safe_check_comfyui_available(url))
            self.assertEqual(ReadonlyComfyUIClient(url).available_models,
                             ["synthetic.safetensors"])

    def test_declared_large_content_length_rejected_before_body(self):
        self.assert_rejected(make_payload(),
                             {"Content-Length": str(MAX_DISCOVERY_BYTES + 1)})

    def test_absurdly_long_content_length_header_rejected_safely(self):
        self.assert_rejected(make_payload(),
                             {"Content-Length": "9" * 5000})

    def test_invalid_content_length_header_rejected_safely(self):
        self.assert_rejected(make_payload(), {"Content-Length": "unknown"})

    def test_unannounced_large_plain_json_is_rejected(self):
        payload = make_payload(extra=MAX_DISCOVERY_BYTES)
        self.assertGreater(len(payload), MAX_DISCOVERY_BYTES)
        self.assert_rejected(payload)

    def test_small_wire_gzip_large_decompressed_json_is_rejected(self):
        payload = gzip.compress(make_payload(extra=MAX_DISCOVERY_BYTES))
        self.assertLess(len(payload), MAX_DISCOVERY_BYTES)
        self.assert_rejected(payload, {
            "Content-Encoding": "gzip",
            "Content-Length": str(len(payload)),
        })

    def test_small_valid_gzip_response_supported(self):
        body = gzip.compress(make_payload())
        with stub_server(body, {"Content-Encoding": "gzip",
                                "Content-Length": str(len(body))}) as (url, state):
            self.assertTrue(safe_check_comfyui_available(url))
            self.assertEqual(ReadonlyComfyUIClient(url).available_models,
                             ["synthetic.safetensors"])
            self.assertEqual(state["posts"], [])

    def test_malformed_json_rejected(self):
        self.assert_rejected(b'{"CheckpointLoaderSimple":')

    def test_nested_json_recursion_rejected(self):
        self.assert_rejected(b"[" * 1500 + b"0" + b"]" * 1500)

    def test_non_dict_json_rejected(self):
        self.assert_rejected(b'["CheckpointLoaderSimple"]')

    def test_wrong_top_level_shape_rejected(self):
        self.assert_rejected(b'{"CheckpointLoaderSimple":null}')

    def test_non_200_rejected_without_post(self):
        self.assert_rejected(b"{}",
                             {"Location": "https://example.com/not-followed"}, status=302)

    def test_misleading_short_content_length_cannot_create_valid_inventory(self):
        body = make_payload()
        self.assert_rejected(body, {"Content-Length": "2"})


if __name__ == "__main__":
    unittest.main()
