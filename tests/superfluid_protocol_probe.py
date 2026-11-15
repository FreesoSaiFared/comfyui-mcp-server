"""Real MCP HTTP protocol probe against an isolated loopback ComfyUI stub.
No GPU, prompt submission, installs, or external effects. Requires SDK v1.
"""
import asyncio
import json
import os
from pathlib import Path
import socket
import socketserver
import subprocess
import sys
import tempfile
import threading
import time
from http.server import BaseHTTPRequestHandler

from mcp import ClientSession
from mcp.client.streamable_http import streamablehttp_client


class Stub(BaseHTTPRequestHandler):
    seen_gets=[]
    seen_posts=[]
    def do_GET(self):
        type(self).seen_gets.append(self.path)
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
        type(self).seen_posts.append(self.path)
        self.send_response(403)
        self.end_headers()

    def log_message(self, *_): pass


async def probe_mcp():
    async with streamablehttp_client("http://127.0.0.1:9000/mcp") as streams:
        read, write = streams[0], streams[1]
        async with ClientSession(read, write) as session:
            await session.initialize()
            listed=await session.list_tools()
            names=sorted(x.name for x in listed.tools)
            expected=["list_models","list_workflows","superfluid_worker_admission"]
            assert names == expected, f"UNEXPECTED_TOOLS {names}"
            result=await session.call_tool("list_models",{})
            assert not result.isError, "READ_ONLY_MODEL_DISCOVERY_FAILED"
            body="\n".join(str(getattr(x,'text','')) for x in result.content)
            assert "stable.safetensors" in body, "MODEL_INVENTORY_NOT_RETURNED"
            denied=await session.call_tool("superfluid_worker_admission",{})
            deny_text="\n".join(str(getattr(x,'text','')) for x in denied.content)
            assert "DENY" in deny_text, "FAIL_CLOSED_TOOL_MISSING"
            rejected=False
            try:
                unauthorized=await session.call_tool("run_workflow",{"workflow_id":"generate_image"})
                rejected=bool(unauthorized.isError)
            except Exception:
                rejected=True
            assert rejected, "EFFECTFUL_TOOL_REACHABLE"
            assert not Stub.seen_posts, "WORKFLOW_WAS_SUBMITTED"
            return {"schema":"superfluid-readonly-protocol-probe-v1",
                    "transport":"real SDK v1 HTTP streamable protocol (not a GPU service)",
                    "registered_tools":names, "models_observed":["models/stable.safetensors"],
                    "unknown_run_workflow_rejected":rejected, "comfyui_post_count":len(Stub.seen_posts),
                    "rights_attested":False,"artifact_hash_attested":False,
                    "execution_permission":False}


def main():
    class Backend(socketserver.ThreadingTCPServer): allow_reuse_address=True
    with Backend(("127.0.0.1",0),Stub) as backend:
        backend.daemon_threads=True
        listener=threading.Thread(target=backend.serve_forever,daemon=True)
        listener.start()
        env=os.environ.copy()
        env.update({"SUPERFLUID_MODE":"readonly","COMFYUI_URL":f"http://127.0.0.1:{backend.server_address[1]}"})
        with tempfile.TemporaryDirectory(prefix="mcp-probe-") as tmp:
            log=open(Path(tmp)/"server.log","wb")
            p=subprocess.Popen([sys.executable,"-u","server.py"],env=env,stdout=log,stderr=subprocess.STDOUT)
            try:
                ready=False
                for _ in range(120):
                    if p.poll() is not None: break
                    try:
                        with socket.create_connection(("127.0.0.1",9000),timeout=.3):
                            ready=True
                            break
                    except OSError:time.sleep(.1)
                if not ready:
                    log.close()
                    raise RuntimeError("MCP_SERVER_NOT_LISTENING: "+Path(tmp,"server.log").read_text(errors='replace')[-2500:])
                result=asyncio.run(probe_mcp())
                print(json.dumps(result,indent=2,sort_keys=True),flush=True)
            finally:
                p.terminate()
                try:p.wait(timeout=6)
                except subprocess.TimeoutExpired:
                    p.kill(); p.wait()
                log.close()
                backend.shutdown()
                listener.join(timeout=3)


if __name__=="__main__":main()
