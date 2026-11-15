"""M099: exactly one guarded GET during readonly server startup, no retry.

Only ephemeral synthetic 127.0.0.1 stubs. No actual GPU/ComfyUI,
installation, paid rental, model download, POST or production access.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
import socketserver
import subprocess
import sys
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler
from unittest.mock import patch

from superfluid_safe_comfy import ReadonlyBoundaryDenied, ReadonlyComfyUIClient


class SnapshotBoundary(unittest.TestCase):
    def test_reuses_validated_snapshot_without_network(self):
        payload = {"CheckpointLoaderSimple": {"input": {"required": {
            "ckpt_name": [["first.safetensors", "second.safetensors"]]}}}}
        with patch.object(ReadonlyComfyUIClient, "_get_available_models", side_effect=AssertionError("SECOND_GET_FORBIDDEN")):
            client = ReadonlyComfyUIClient.from_observed_payload("http://127.0.0.1:8188", payload)
        self.assertEqual(client.available_models, ["first.safetensors", "second.safetensors"])
        self.assertEqual(client.base_url, "http://127.0.0.1:8188")

    def test_unauthenticated_snapshot_never_proves_execution(self):
        from superfluid_readonly import model_inventory
        payload = {"CheckpointLoaderSimple": {"input": {"required": {
            "ckpt_name": [["claimed/synthetic.safetensors"]]}}}}
        client = ReadonlyComfyUIClient.from_observed_payload("http://127.0.0.1:8188", payload)
        inventory = model_inventory(client.available_models)
        self.assertEqual(inventory["status"], "OBSERVED_ONLY")
        self.assertEqual(inventory["verified_artifact_count"], 0)
        self.assertFalse(inventory["execution_authorized"])

    def test_invalid_snapshot_rejected_without_network(self):
        for payload in (None, [], {}, {"CheckpointLoaderSimple": None}, {"CheckpointLoaderSimple": []}):
            with self.subTest(payload=payload):
                with patch.object(ReadonlyComfyUIClient, "_get_available_models", side_effect=AssertionError("NETWORK_FORBIDDEN")):
                    with self.assertRaisesRegex(ReadonlyBoundaryDenied, "INVALID_READONLY_DISCOVERY_SNAPSHOT"):
                        ReadonlyComfyUIClient.from_observed_payload("http://127.0.0.1:8188", payload)

    def test_invalid_loopback_origin_rejected(self):
        with self.assertRaisesRegex(ReadonlyBoundaryDenied, "UNSAFE_COMFYUI_URL"):
            ReadonlyComfyUIClient.from_observed_payload("http://example.com:8188", {"CheckpointLoaderSimple": {}})

    def test_malformed_nested_snapshot_is_denied_not_empty(self):
        malformed = [
            {"CheckpointLoaderSimple": {}},
            {"CheckpointLoaderSimple": {"input": "untrusted"}},
            {"CheckpointLoaderSimple": {"input": {}}},
            {"CheckpointLoaderSimple": {"input": {"required": {}}}},
            {"CheckpointLoaderSimple": {"input": {"required": {"ckpt_name": []}}}},
            {"CheckpointLoaderSimple": {"input": {"required": {"ckpt_name": ["bad"]}}}},
            {"CheckpointLoaderSimple": {"input": {"required": {"ckpt_name": [[None]]}}}},
        ]
        for payload in malformed:
            with self.subTest(payload=payload):
                with self.assertRaisesRegex(ReadonlyBoundaryDenied, "INVALID_READONLY_DISCOVERY_SNAPSHOT"):
                    ReadonlyComfyUIClient.from_observed_payload("http://127.0.0.1:8188", payload)

    def test_valid_empty_choices_are_observed_not_unavailable(self):
        from superfluid_readonly import model_inventory
        valid_empty = {"CheckpointLoaderSimple": {"input": {"required": {"ckpt_name": [[]]}}}}
        client = ReadonlyComfyUIClient.from_observed_payload("http://127.0.0.1:8188", valid_empty)
        self.assertEqual(client.available_models, [])
        decision = model_inventory(client.available_models)
        self.assertEqual(decision["status"], "OBSERVED_ONLY")
        self.assertEqual(decision["count"], 0)
        self.assertFalse(decision["execution_authorized"])


class OneShotBackend(BaseHTTPRequestHandler):
    requests = []
    posts = 0
    first_status = 200
    first_payload = {"CheckpointLoaderSimple": {"input": {"required": {
        "ckpt_name": [["first/synthetic.safetensors"]]}}}}
    second_payload = {"CheckpointLoaderSimple": {"input": {"required": {
        "ckpt_name": [["second/changed.safetensors"]]}}}}

    def do_GET(self):
        type(self).requests.append(self.path)
        first = len(type(self).requests) == 1
        data = self.first_payload if first else self.second_payload
        body = data if type(data) is bytes else json.dumps(data).encode()
        self.send_response(self.first_status if first else 200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self):
        type(self).posts += 1
        self.send_response(403)
        self.end_headers()

    def log_message(self, *_):
        pass


class OneShotStartup(unittest.TestCase):
    def run_child(self, *, status=200, first_payload=None):
        class Backend(socketserver.ThreadingTCPServer):
            allow_reuse_address = True
            daemon_threads = True
        OneShotBackend.requests.clear()
        OneShotBackend.posts = 0
        OneShotBackend.first_status = status
        OneShotBackend.first_payload = first_payload or {"CheckpointLoaderSimple": {
            "input": {"required": {"ckpt_name": [["first/synthetic.safetensors"]]}}}}
        with Backend(("127.0.0.1", 0), OneShotBackend) as backend:
            t = threading.Thread(target=backend.serve_forever, daemon=True)
            t.start()
            try:
                with tempfile.TemporaryDirectory(prefix="m099-oneshot-") as d:
                    env = os.environ.copy()
                    env.update({
                        "SUPERFLUID_MODE": "readonly",
                        "COMFYUI_URL": f"http://127.0.0.1:{backend.server_address[1]}",
                        "COMFY_MCP_WORKFLOW_DIR": d,
                        "HTTP_PROXY": "http://127.0.0.1:1",
                        "HTTPS_PROXY": "http://127.0.0.1:1",
                        "NO_PROXY": "",
                    })
                    snippet = (
                        "import json,server; "
                        "print('M099_STARTUP_RECEIPT:'+json.dumps({"
                        "'models':server.comfyui_client.available_models,"
                        "'tools':sorted(t.name for t in server.mcp._tool_manager.list_tools()),"
                        "'mode':server.SUPERFLUID_MODE}))"
                    )
                    result = subprocess.run(
                        [sys.executable, "-c", snippet],
                        cwd=Path(__file__).resolve().parent.parent,
                        env=env, capture_output=True, text=True, timeout=15,
                    )
                return result, OneShotBackend.requests.copy(), OneShotBackend.posts
            finally:
                backend.shutdown()
                t.join(timeout=4)

    def test_real_readonly_server_uses_one_get_and_first_snapshot(self):
        proc, gets, posts = self.run_child()
        self.assertEqual(proc.returncode, 0, proc.stderr[-3000:])
        receipts = [json.loads(x.split("M099_STARTUP_RECEIPT:", 1)[1])
                    for x in proc.stdout.splitlines() if "M099_STARTUP_RECEIPT:" in x]
        self.assertEqual(len(receipts), 1)
        self.assertEqual(receipts[0]["models"], ["first/synthetic.safetensors"])
        self.assertEqual(receipts[0]["mode"], "readonly")
        self.assertEqual(receipts[0]["tools"], ["list_models", "list_workflows", "superfluid_worker_admission"])
        self.assertEqual(gets, ["/object_info/CheckpointLoaderSimple"])
        self.assertEqual(posts, 0)

    def test_invalid_first_response_fails_without_retrying(self):
        proc, gets, posts = self.run_child(first_payload={"wrong_schema": True})
        self.assertNotEqual(proc.returncode, 0)
        self.assertIn("READONLY_DISCOVERY_UNAVAILABLE", proc.stderr + proc.stdout)
        self.assertEqual(gets, ["/object_info/CheckpointLoaderSimple"])
        self.assertEqual(posts, 0)

    def test_invalid_nested_first_response_fails_with_one_get(self):
        payload = {"CheckpointLoaderSimple": {"input": {"required": {}}}}
        proc, gets, posts = self.run_child(first_payload=payload)
        self.assertNotEqual(proc.returncode, 0)
        self.assertIn("READONLY_DISCOVERY_UNAVAILABLE", proc.stderr + proc.stdout)
        self.assertEqual(gets, ["/object_info/CheckpointLoaderSimple"])
        self.assertEqual(posts, 0)

    def test_valid_empty_first_response_preserves_one_get(self):
        payload = {"CheckpointLoaderSimple": {"input": {"required": {"ckpt_name": [[]]}}}}
        proc, gets, posts = self.run_child(first_payload=payload)
        self.assertEqual(proc.returncode, 0, proc.stderr[-2000:])
        receipts = [json.loads(x.split("M099_STARTUP_RECEIPT:", 1)[1])
                    for x in proc.stdout.splitlines() if "M099_STARTUP_RECEIPT:" in x]
        self.assertEqual(len(receipts), 1)
        self.assertEqual(receipts[0]["models"], [])
        self.assertEqual(gets, ["/object_info/CheckpointLoaderSimple"])
        self.assertEqual(posts, 0)

    def test_duplicate_key_first_response_exits_without_retry(self):
        raw = (b'{"CheckpointLoaderSimple":{"input":{"required":'
               b'{"ckpt_name":[[]],"ckpt_name":[["forged.safetensors"]]}}}}')
        proc, gets, posts = self.run_child(first_payload=raw)
        self.assertNotEqual(proc.returncode, 0)
        self.assertIn("READONLY_DISCOVERY_UNAVAILABLE", proc.stderr + proc.stdout)
        self.assertEqual(gets, ["/object_info/CheckpointLoaderSimple"])
        self.assertEqual(posts, 0)

    def test_server_error_fails_without_retrying(self):
        proc, gets, posts = self.run_child(status=503)
        self.assertNotEqual(proc.returncode, 0)
        self.assertIn("READONLY_DISCOVERY_UNAVAILABLE", proc.stderr + proc.stdout)
        self.assertEqual(gets, ["/object_info/CheckpointLoaderSimple"])
        self.assertEqual(posts, 0)


if __name__ == "__main__":
    unittest.main()
