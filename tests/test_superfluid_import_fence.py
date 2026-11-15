"""M091: verify fresh-process readonly import graph excludes legacy execution code.

Tests use a single ephemeral loopback stub and isolated Python child processes.
No real ComfyUI, GPU, model installation or external network.
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

FORBIDDEN = (
    "comfyui_client",
    "managers.asset_registry",
    "managers.defaults_manager",
    "managers.publish_manager",
    "managers.workflow_manager",
    "tools.asset",
    "tools.configuration",
    "tools.generation",
    "tools.job",
    "tools.publish",
    "tools.workflow",
)

# This runs inside an isolated child process before importing the actual server.
# The guard blocks effectful project modules even if the read-only mode tries to
# import them through a different path or transitive dependency.
CHILD = """
import importlib.abc
import json
import sys

FORBIDDEN = {forbidden!r}
class LegacyImportDenied(importlib.abc.MetaPathFinder):
    def find_spec(self, fullname, path=None, target=None):
        if any(fullname == prefix or fullname.startswith(prefix + '.') for prefix in FORBIDDEN):
            raise RuntimeError('M091_EFFECTFUL_IMPORT_BLOCKED:' + fullname)
        return None
sys.meta_path.insert(0, LegacyImportDenied())

import server
loaded = sorted(name for name in sys.modules
                if any(name == prefix or name.startswith(prefix + '.') for prefix in FORBIDDEN))
if loaded:
    raise RuntimeError('M091_LEGACY_MODULE_ALREADY_LOADED:' + repr(loaded))
names = sorted(tool.name for tool in server.mcp._tool_manager.list_tools())
assert names == ['list_models','list_workflows','superfluid_worker_admission'], names
assert server.SUPERFLUID_MODE == 'readonly'
assert server.comfyui_client.__class__.__name__ == 'ReadonlyComfyUIClient'
assert server.workflow_manager.__class__.__name__ == 'ReadonlyWorkflowCatalog'
assert server.asset_registry is None and server.publish_manager is None
print('M091_IMPORT_RECEIPT:' + json.dumps(dict(
    result='DENY', rejected_effectful_imports=True, loaded_legacy_modules=loaded,
    registered_tools=names, gpu_execution=False, real_gpu_host_inspected=False
), sort_keys=True))
"""


class Stub(BaseHTTPRequestHandler):
    gets = []
    posts = []

    def do_GET(self):
        type(self).gets.append(self.path)
        payload = b'{"CheckpointLoaderSimple":{"input":{"required":{"ckpt_name":[["synthetic.safetensors"]]}}}}'
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def do_POST(self):
        type(self).posts.append(self.path)
        self.send_response(403)
        self.end_headers()

    def log_message(self, *_):
        pass


class ImportFenceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.root = Path(__file__).resolve().parent.parent

    def child(self, env, script=CHILD, *, timeout=25):
        return subprocess.run(
            [sys.executable, "-c", script.format(forbidden=FORBIDDEN)],
            cwd=self.root, env=env, capture_output=True, text=True, timeout=timeout
        )

    def test_readonly_startup_excludes_effectful_imports(self):
        Stub.gets.clear()
        Stub.posts.clear()

        class Backend(socketserver.ThreadingTCPServer):
            allow_reuse_address = True
            daemon_threads = True

        with Backend(("127.0.0.1", 0), Stub) as http:
            t = threading.Thread(target=http.serve_forever, daemon=True)
            t.start()
            try:
                with tempfile.TemporaryDirectory(prefix="m091-readonly-") as d:
                    env = os.environ.copy()
                    env.update({
                        "SUPERFLUID_MODE": "readonly",
                        "COMFYUI_URL": f"http://127.0.0.1:{http.server_address[1]}",
                        "COMFY_MCP_WORKFLOW_DIR": d,
                        "HTTP_PROXY": "http://127.0.0.1:1",
                        "HTTPS_PROXY": "http://127.0.0.1:1",
                        "NO_PROXY": "",
                    })
                    p = self.child(env)
                self.assertEqual(p.returncode, 0, p.stderr[-2000:])
                receipts = [x.removeprefix("M091_IMPORT_RECEIPT:") for x in p.stdout.splitlines()
                            if x.startswith("M091_IMPORT_RECEIPT:")]
                self.assertEqual(len(receipts), 1, p.stdout[-2000:])
                result = json.loads(receipts[0])
                self.assertEqual(result["result"], "DENY")
                self.assertEqual(result["loaded_legacy_modules"], [])
                self.assertEqual(result["registered_tools"],
                                 ["list_models", "list_workflows", "superfluid_worker_admission"])
                self.assertEqual(Stub.posts, [])
                self.assertEqual(Stub.gets,
                                 ["/object_info/CheckpointLoaderSimple"])
            finally:
                http.shutdown()
                t.join(timeout=4)

    def test_legacy_without_ack_rejected_before_loading_modules(self):
        env = os.environ.copy()
        env.update({"SUPERFLUID_MODE": "legacy", "COMFYUI_URL": "http://127.0.0.1:1"})
        env.pop("SUPERFLUID_UNSAFE_LEGACY_ACK", None)
        p = self.child(env)
        self.assertNotEqual(p.returncode, 0)
        self.assertIn("LEGACY_EFFECTS_REQUIRE_EXPLICIT_RISK_ACK", p.stdout + p.stderr)
        self.assertNotIn("M091_EFFECTFUL_IMPORT_BLOCKED", p.stdout + p.stderr)

    def test_explicit_legacy_ack_still_takes_separate_effectful_path(self):
        env = os.environ.copy()
        env.update({"SUPERFLUID_MODE": "legacy", "COMFYUI_URL": "http://127.0.0.1:1",
                    "SUPERFLUID_UNSAFE_LEGACY_ACK": "YES_I_ACCEPT_UNGUARDED_PROMPT"})
        p = self.child(env)
        self.assertNotEqual(p.returncode, 0)
        self.assertIn("M091_EFFECTFUL_IMPORT_BLOCKED:comfyui_client", p.stdout + p.stderr)

    def test_invalid_mode_rejected_before_loading_modules(self):
        env = os.environ.copy()
        env.update({"SUPERFLUID_MODE": "unsafe_unknown_mode"})
        p = self.child(env)
        self.assertNotEqual(p.returncode, 0)
        self.assertIn("SUPERFLUID_MODE must be legacy or readonly", p.stdout + p.stderr)
        self.assertNotIn("M091_EFFECTFUL_IMPORT_BLOCKED", p.stdout + p.stderr)


if __name__ == "__main__":
    unittest.main()
