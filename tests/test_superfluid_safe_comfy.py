"""Adversarial tests for the SUPERFLUID fail-closed host-facing boundary."""
from __future__ import annotations

import os
import subprocess
import sys
import threading
import unittest
import socketserver
from http.server import BaseHTTPRequestHandler
from unittest.mock import patch

from superfluid_safe_comfy import (
    ReadonlyComfyUIClient, ReadonlyBoundaryDenied, validate_loopback_comfy_url
)


class BoundaryTests(unittest.TestCase):
    def test_allow_only_literal_loopback_origin(self):
        self.assertEqual(validate_loopback_comfy_url("http://127.0.0.1:8188/"), "http://127.0.0.1:8188")
        self.assertEqual(validate_loopback_comfy_url("http://[::1]:8188"), "http://[::1]:8188")
        for url in [
            "http://localhost:8188", "http://127.0.0.2:8188",
            "http://0.0.0.0:8188", "http://8.8.8.8:8188",
            "http://2130706433:8188", "http://[::ffff:127.0.0.1]:8188",
            "http://127.0.0.1:8188/x", "http://127.0.0.1:8188/../x",
            "http://127.0.0.1:8188?evil=1", "http://127.0.0.1:8188#fragment",
            "http://user:secret@127.0.0.1:8188", "file:///tmp/s",
            "http://127.0.0.1", "http://127.0.0.1:0", "http://127.0.0.1:99999",
            "http://127.0.0.1:8188\nX:evil",
        ]:
            with self.subTest(url=url):
                with self.assertRaises(ReadonlyBoundaryDenied):
                    validate_loopback_comfy_url(url)

    def test_direct_effectful_methods_denied_even_if_invoked(self):
        with patch.object(ReadonlyComfyUIClient, "_get_available_models", return_value=[]):
            c=ReadonlyComfyUIClient("http://127.0.0.1:8188")
        with patch("requests.post", side_effect=AssertionError("POST_FORBIDDEN")):
            with self.assertRaisesRegex(ReadonlyBoundaryDenied,"NO_PROMPT"):
                c._queue_workflow({"1":{"class_type":"KSampler"}})
            with self.assertRaisesRegex(ReadonlyBoundaryDenied,"NO_PROMPT"):
                c.run_custom_workflow({"1":{"class_type":"KSampler"}})
            with self.assertRaisesRegex(ReadonlyBoundaryDenied,"NO_CANCEL"):
                c.cancel_prompt("a")
    
    def test_legacy_mode_requires_explicit_ack_before_network(self):
        env=os.environ.copy()
        env.update({"SUPERFLUID_MODE":"legacy","COMFYUI_URL":"http://127.0.0.1:1"})
        env.pop("SUPERFLUID_UNSAFE_LEGACY_ACK",None)
        p=subprocess.run([sys.executable,"-c","import server"],env=env,
                         capture_output=True,text=True,timeout=15)
        self.assertNotEqual(p.returncode,0)
        self.assertIn("LEGACY_EFFECTS_REQUIRE_EXPLICIT_RISK_ACK",p.stdout+p.stderr)

    def test_bad_origin_is_rejected_before_network(self):
        env=os.environ.copy()
        env.pop("SUPERFLUID_MODE",None)
        env["COMFYUI_URL"]="http://example.com:8188"
        p=subprocess.run([sys.executable,"-c","import server"],env=env,
                         capture_output=True,text=True,timeout=15)
        self.assertNotEqual(p.returncode,0)
        self.assertIn("UNSAFE_COMFYUI_URL",p.stdout+p.stderr)

class Stub(BaseHTTPRequestHandler):
    get_paths=[]
    post_paths=[]
    def do_GET(self):
        self.__class__.get_paths.append(self.path)
        if self.path == "/object_info/CheckpointLoaderSimple":
            payload=b'{"CheckpointLoaderSimple":{"input":{"required":{"ckpt_name":[["untrusted.safetensors"]]}}}}'
            status=200
        else:
            status=404;payload=b'{}'
        self.send_response(status)
        self.send_header("Content-Length",str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)
    def do_POST(self):
        self.__class__.post_paths.append(self.path)
        self.send_response(403)
        self.end_headers()
    def log_message(self,*args):pass


class HttpTests(unittest.TestCase):
    def test_live_loopback_get_only_and_no_proxy(self):
        class Reuse(socketserver.ThreadingTCPServer):allow_reuse_address=True
        Stub.get_paths.clear()
        Stub.post_paths.clear()
        with Reuse(("127.0.0.1",0),Stub) as http:
            t=threading.Thread(target=http.serve_forever,daemon=True)
            t.start()
            try:
                with patch.dict(os.environ,{"HTTP_PROXY":"http://127.0.0.1:1","HTTPS_PROXY":"http://127.0.0.1:1","NO_PROXY":""}):
                    c=ReadonlyComfyUIClient(f"http://127.0.0.1:{http.server_address[1]}")
                    self.assertEqual(c.available_models,["untrusted.safetensors"])
                self.assertEqual(Stub.get_paths,["/object_info/CheckpointLoaderSimple"])
                self.assertEqual(Stub.post_paths,[])
            finally:
                http.shutdown(); t.join(timeout=4)

    def test_redirect_never_followed(self):
        class Redirect(BaseHTTPRequestHandler):
            requests=[]
            def do_GET(self):
                self.__class__.requests.append(self.path)
                self.send_response(302)
                self.send_header("Location","https://example.com/secret")
                self.end_headers()
            def log_message(self,*args):pass
        class Reuse(socketserver.ThreadingTCPServer):allow_reuse_address=True
        with Reuse(("127.0.0.1",0),Redirect) as http:
            t=threading.Thread(target=http.serve_forever,daemon=True);t.start()
            try:
                c=ReadonlyComfyUIClient(f"http://127.0.0.1:{http.server_address[1]}")
                self.assertEqual(c.available_models,[])
                self.assertEqual(Redirect.requests,["/object_info/CheckpointLoaderSimple"])
            finally:
                http.shutdown();t.join(timeout=4)


if __name__ == "__main__":
    unittest.main()
