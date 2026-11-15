"""SUPERFLUID review-only tests for the real owner fork MCP registration."""
import importlib
import json
import os
import socketserver
import sys
import threading
import unittest
from http.server import BaseHTTPRequestHandler

from superfluid_readonly import model_inventory, workflow_inventory, register_superfluid_readonly_tools


class CapturingMcp:
    def __init__(self): self.tools = {}
    def tool(self):
        def wrap(fn):
            if fn.__name__ in self.tools: raise AssertionError("duplicate tool")
            self.tools[fn.__name__] = fn
            return fn
        return wrap


class FakeClient:
    available_models = ["models/stable.safetensors"]


class FakeWorkflows:
    def get_workflow_catalog(self):
        return [{"id": "video_prepare", "name": "Video Prepare", "hash": "untrusted metadata"}]


class ReadonlyContracts(unittest.TestCase):
    def test_allowlist_only(self):
        m=CapturingMcp()
        register_superfluid_readonly_tools(m, FakeClient(), FakeWorkflows())
        self.assertEqual(set(m.tools), {"list_models", "list_workflows", "superfluid_worker_admission"})
        self.assertEqual(m.tools["list_models"]()["verified_artifact_count"],0)
        self.assertFalse(m.tools["list_models"]()["execution_authorized"])
        self.assertEqual(m.tools["list_workflows"]()["verified_workflow_count"],0)
        self.assertFalse(m.tools["superfluid_worker_admission"]()["prompt_submission_allowed"])

    def test_no_hash_or_rights_claim_from_filename(self):
        result=model_inventory(["models/stable.safetensors"])
        self.assertEqual(result["status"],"OBSERVED_ONLY")
        self.assertNotIn("verified_hash",result)
        self.assertNotIn("rights_grant",result)

    def test_traversal_and_ambiguous_inputs_fail(self):
        for val in ["../secrets", "/tmp/weights", "bad\\models", "hello%2Ffile", "foo//bar", "x\ny", "folder/../x"]:
            with self.subTest(val=repr(val)):
                self.assertEqual(model_inventory([val])["status"],"DENY")
        self.assertEqual(model_inventory(["duplicate", "duplicate"])["status"],"DENY")
        self.assertEqual(model_inventory("not a list")["status"],"DENY")
        self.assertEqual(model_inventory(["x"]*501)["status"],"DENY")

    def test_workflow_catalog_cannot_grant_hashes(self):
        result=workflow_inventory([{"id":"video_prepare","name":"Video Prepare","hash":"claimed","command":"POST /prompt"}])
        self.assertEqual(result["workflows"],[{"id":"video_prepare","name":"Video Prepare"}])
        self.assertFalse(result["execution_authorized"])
        for bad in [[{"id":"../bad","name":"x"}],[{"id":"x","name":"bad\nname"}],
                    [{"id":"same","name":"a"},{"id":"same","name":"b"}]]:
            self.assertEqual(workflow_inventory(bad)["status"],"DENY")


class StubComfy(BaseHTTPRequestHandler):
    post_count=0
    get_paths=[]
    def do_GET(self):
        type(self).get_paths.append(self.path)
        if self.path == "/object_info/CheckpointLoaderSimple":
            body=json.dumps({"CheckpointLoaderSimple":{"input":{"required":{"ckpt_name":[["models/stable.safetensors"]]}}}}).encode()
        else:
            body=b"{}"
        self.send_response(200)
        self.send_header("Content-Type","application/json")
        self.send_header("Content-Length",str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self):
        type(self).post_count += 1
        self.send_response(403)
        self.end_headers()

    def log_message(self,*args): pass


class ActualUpstreamRegistration(unittest.TestCase):
    def test_server_registers_readonly_tools_without_effects(self):
        class ReuseServer(socketserver.ThreadingTCPServer): allow_reuse_address=True
        with ReuseServer(("127.0.0.1",0),StubComfy) as backend:
            port=backend.server_address[1]
            thread=threading.Thread(target=backend.serve_forever,daemon=True)
            thread.start()
            old={k:os.environ.get(k) for k in ["SUPERFLUID_MODE","COMFYUI_URL"]}
            try:
                os.environ["SUPERFLUID_MODE"]="readonly"
                os.environ["COMFYUI_URL"]=f"http://127.0.0.1:{port}"
                sys.modules.pop("server",None)
                server=importlib.import_module("server")
                names={t.name for t in server.mcp._tool_manager.list_tools()}
                self.assertEqual(names, {"list_models","list_workflows","superfluid_worker_admission"})
                self.assertIsNone(server.publish_manager)
                self.assertEqual(StubComfy.post_count,0)
                self.assertIn("/object_info/CheckpointLoaderSimple",StubComfy.get_paths)
            finally:
                for k,v in old.items():
                    if v is None:os.environ.pop(k,None)
                    else:os.environ[k]=v
                backend.shutdown()
                thread.join(timeout=5)


if __name__=="__main__":unittest.main()
