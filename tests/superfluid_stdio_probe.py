"""M089: real SDK-v1 MCP stdio protocol acceptance using a synthetic loopback stub.

No GPU, real ComfyUI, paid compute, models, downloads or external network.
Fails if startup banners corrupt JSON-RPC stdout framing.
"""
from __future__ import annotations

import asyncio
import json
import os
from pathlib import Path
import socketserver
import sys
import tempfile
import threading
from http.server import BaseHTTPRequestHandler

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client


class Stub(BaseHTTPRequestHandler):
    get_paths = []
    post_paths = []

    def do_GET(self):
        type(self).get_paths.append(self.path)
        if self.path == "/object_info/CheckpointLoaderSimple":
            body = json.dumps({"CheckpointLoaderSimple": {
                "input": {"required": {"ckpt_name": [["models/synthetic.safetensors"]]}}
            }}).encode()
        else:
            body = b"{}"
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self):
        type(self).post_paths.append(self.path)
        self.send_response(403)
        self.end_headers()

    def log_message(self, *_):
        pass


async def probe(url: str, workflow_dir: str) -> dict:
    env = os.environ.copy()
    env.update({
        "SUPERFLUID_MODE": "readonly",
        "COMFYUI_URL": url,
        "COMFY_MCP_WORKFLOW_DIR": workflow_dir,
        "PYTHONUNBUFFERED": "1",
    })
    params = StdioServerParameters(
        command=sys.executable,
        args=["-u", str(Path(__file__).resolve().parent.parent / "server.py"), "--stdio"],
        env=env,
    )
    # SDK stdio_client validates JSON-RPC frames: banners on stdout break this.
    async with stdio_client(params) as streams:
        read, write = streams[0], streams[1]
        async with ClientSession(read, write) as session:
            await session.initialize()
            listing = await session.list_tools()
            names = sorted(x.name for x in listing.tools)
            expected = ["list_models", "list_workflows", "superfluid_worker_admission"]
            assert names == expected, f"UNEXPECTED_TOOLS: {names}"
            models = await session.call_tool("list_models", {})
            assert not models.isError, "MODEL_DISCOVERY_FAILED"
            models_text = "\n".join(str(getattr(x, "text", "")) for x in models.content)
            assert "synthetic.safetensors" in models_text, "SYNTHETIC_MODEL_NOT_VISIBLE"
            admission = await session.call_tool("superfluid_worker_admission", {})
            admission_text = "\n".join(str(getattr(x, "text", "")) for x in admission.content)
            assert "DENY" in admission_text, "ADMISSION_NOT_DENIED"
            rejected = False
            try:
                unauthorized = await session.call_tool("run_workflow", {"workflow_id": "forbidden"})
                rejected = bool(unauthorized.isError)
            except Exception:
                rejected = True
            assert rejected, "EFFECTFUL_TOOL_WAS_REACHABLE"
            assert Stub.post_paths == [], "COMFYUI_RECEIVED_POST"
            return {
                "schema": "superfluid.m089.real-stdio-protocol.v1",
                "transport": "SDK v1 stdio subprocess with JSON-RPC over stdout",
                "synthetic_backend": True,
                "tools": names,
                "model_discovery_succeeded": True,
                "admission": "DENY",
                "unauthorized_run_rejected": rejected,
                "comfyui_stub_post_count": len(Stub.post_paths),
                "actual_gpu_host_inspected": False,
                "execution_authorized": False,
            }


def main() -> None:
    class Backend(socketserver.ThreadingTCPServer):
        allow_reuse_address = True
        daemon_threads = True

    with Backend(("127.0.0.1", 0), Stub) as backend:
        thread = threading.Thread(target=backend.serve_forever, daemon=True)
        thread.start()
        try:
            with tempfile.TemporaryDirectory(prefix="m089-stdio-") as tmp:
                result = asyncio.run(asyncio.wait_for(
                    probe(f"http://127.0.0.1:{backend.server_address[1]}", tmp),
                    timeout=35,
                ))
            assert "/object_info/CheckpointLoaderSimple" in Stub.get_paths
            print(json.dumps(result, indent=2, sort_keys=True), flush=True)
        finally:
            backend.shutdown()
            thread.join(timeout=4)


if __name__ == "__main__":
    main()
