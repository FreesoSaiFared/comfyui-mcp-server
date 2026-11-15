"""M098: complete HTTP request deadline regression against locally owned stubs.

Synthetic ephemeral loopback only: no real ComfyUI, GPU or remote traffic.
"""
from __future__ import annotations
import asyncio
import json
import socketserver
import threading
import time
import unittest
from contextlib import contextmanager
from unittest.mock import patch

import superfluid_safe_comfy as guard
from superfluid_safe_comfy import ReadonlyComfyUIClient, safe_check_comfyui_available

PAYLOAD = json.dumps({"CheckpointLoaderSimple": {
    "input": {"required": {"ckpt_name": [["synthetic.safetensors"]]}}
}}).encode()

@contextmanager
def wire_stub(*, drip_headers=0.0, drip_body=0.0, padding=32):
    observed = {"get": 0, "post": 0, "sent": 0}
    class Handler(socketserver.BaseRequestHandler):
        def handle(self):
            self.request.settimeout(1.5)
            try:
                request = self.request.recv(8192)
                if request.startswith(b"POST "):
                    observed["post"] += 1
                elif request.startswith(b"GET /object_info/CheckpointLoaderSimple "):
                    observed["get"] += 1
                else:
                    return
                header = (b"HTTP/1.1 200 OK\r\nX-Pad: " + b"Q"*padding +
                          b"\r\nContent-Length: " + str(len(PAYLOAD)).encode() + b"\r\n\r\n")
                for b in header:
                    self.request.sendall(bytes([b]))
                    observed["sent"] += 1
                    if drip_headers: time.sleep(drip_headers)
                for b in PAYLOAD:
                    self.request.sendall(bytes([b]))
                    if drip_body: time.sleep(drip_body)
            except (ConnectionResetError, BrokenPipeError, TimeoutError, OSError):
                pass
    class Server(socketserver.ThreadingTCPServer):
        allow_reuse_address = True
        daemon_threads = True
    with Server(("127.0.0.1",0),Handler) as server:
        thread = threading.Thread(target=server.serve_forever,daemon=True)
        thread.start()
        try:
            yield f"http://127.0.0.1:{server.server_address[1]}", observed
        finally:
            server.shutdown();thread.join(timeout=3)

class TransactionDeadlineTests(unittest.TestCase):
    def test_slow_http_headers_hit_total_deadline_not_idle_timeout(self):
        # Send every header byte within the read idle timeout. M093's per-read
        # timeout misses this entirely; the new 0.24 s deadline must expire.
        with wire_stub(drip_headers=0.025,padding=75) as (url, observed):
            with patch.object(guard,"MAX_DISCOVERY_BODY_SECONDS",0.24):
                started = time.monotonic()
                self.assertFalse(safe_check_comfyui_available(url))
                elapsed = time.monotonic()-started
            self.assertLess(elapsed, 0.9, elapsed)
            self.assertEqual(observed["post"],0)
            self.assertEqual(observed["get"],1)

    def test_header_deadline_applies_to_model_inventory(self):
        with wire_stub(drip_headers=0.025,padding=60) as (url, observed):
            with patch.object(guard,"MAX_DISCOVERY_BODY_SECONDS",0.2):
                started=time.monotonic()
                self.assertIsNone(ReadonlyComfyUIClient(url).available_models)
                self.assertLess(time.monotonic()-started,0.9)
            self.assertEqual(observed["post"],0)

    def test_cumulative_header_and_body_delay_expires(self):
        with wire_stub(drip_headers=0.001,drip_body=0.004,padding=32) as (url, observed):
            with patch.object(guard,"MAX_DISCOVERY_BODY_SECONDS",0.18):
                started=time.monotonic()
                self.assertFalse(safe_check_comfyui_available(url))
                self.assertLess(time.monotonic()-started,0.8)
            self.assertEqual(observed["post"],0)

    def test_healthy_request_succeeds_within_budget(self):
        with wire_stub() as (url, observed):
            self.assertTrue(safe_check_comfyui_available(url))
            self.assertEqual(ReadonlyComfyUIClient(url).available_models,["synthetic.safetensors"])
            self.assertEqual(observed["get"],2)
            self.assertEqual(observed["post"],0)

    def test_running_async_event_loop_fails_closed_without_nested_runner(self):
        async def run():
            return safe_check_comfyui_available("http://127.0.0.1:8188")
        self.assertFalse(asyncio.run(run()))

if __name__=="__main__": unittest.main()
