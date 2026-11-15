"""M088: real Linux kernel /proc TCP socket evidence; loopback only, no GPU/HTTP.

These tests do not use synthetic proc files. They create isolated local listener
processes with ephemeral loopback ports; no HTTP requests or packets are sent.
They only show the observer can decode real Linux procfs socket ownership.
"""
from __future__ import annotations

import json
import os
import select
import socket
import subprocess
import sys
import unittest
from contextlib import ExitStack, contextmanager
from pathlib import Path

from superfluid_host_observer import collect_snapshot, _snapshot_process


# The process creates exactly one loopback listener and stays alive until stdin
# closes. It neither accepts connections nor accesses any external network.
_LISTEN_CHILD = r'''
import json, socket, sys
port = int(sys.argv[1])
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
s.bind(("127.0.0.1", port))
s.listen(2)
print(json.dumps({"pid": __import__("os").getpid(), "port": s.getsockname()[1]}), flush=True)
sys.stdin.buffer.read()
s.close()
'''


@contextmanager
def child_listener(port: int = 0):
    if type(port) is not int or not 0 <= port <= 65535:
        raise ValueError("INVALID_PORT")
    p = subprocess.Popen(
        [sys.executable, "-u", "-c", _LISTEN_CHILD, str(port)],
        stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        text=True, bufsize=1,
    )
    try:
        ready, _, _ = select.select([p.stdout], [], [], 6)
        if not ready:
            raise RuntimeError("LOCAL_LISTENER_START_TIMEOUT")
        line = p.stdout.readline()
        if not line:
            raise RuntimeError("LOCAL_LISTENER_FAILED: " + p.stderr.read()[:500])
        announcement = json.loads(line)
        assert announcement["pid"] == p.pid
        assert 1 <= announcement["port"] <= 65535
        yield announcement
    finally:
        if p.stdin and not p.stdin.closed:
            p.stdin.close()
        try:
            p.wait(timeout=4)
        except subprocess.TimeoutExpired:
            p.kill()
            p.wait(timeout=4)
        for stream in [p.stdout, p.stderr]:
            if stream:
                stream.close()


@unittest.skipUnless(sys.platform.startswith("linux") and Path("/proc/self/net/tcp").exists()
                     and hasattr(socket, "SO_REUSEPORT"),
                     "requires Linux procfs and SO_REUSEPORT")
class RealKernelListenerTests(unittest.TestCase):
    """Only this local test environment is accessed; never any worker host."""

    def observe(self, a, b):
        return collect_snapshot("synthetic-local-kernel", a["pid"], b["pid"],
                                a["port"], b["port"])

    def assert_deny(self, r):
        self.assertEqual(r["status"], "DENY")
        self.assertFalse(r["execution_authorized"])
        self.assertFalse(r["prompt_submission_allowed"])
        self.assertFalse(r["host_isolation_proven"])
        self.assertFalse(r["network_calls_performed"])
        self.assertFalse(r["gpu_inference_performed"])

    def test_actual_procfs_two_processes_loopback_are_still_unverified(self):
        with ExitStack() as s:
            a = s.enter_context(child_listener())
            b = s.enter_context(child_listener())
            r = self.observe(a, b)
            self.assert_deny(r)
            self.assertEqual(r["assessment"], "UNVERIFIED", r["blockers"])
            self.assertEqual(r["blockers"], [])
            self.assertEqual(r["schema"], "superfluid.host-proc-snapshot.v2")
            for role, entry in [("comfyui", a), ("mcp", b)]:
                p = r["observed_processes"][role]
                self.assertEqual(p["pid"], entry["pid"])
                self.assertIn({"bind_ip": "127.0.0.1", "port": entry["port"]},
                              p["tcp_listeners"])
                self.assertEqual(p["namespace_extra_listener_count_on_expected_port"], 0)
            self.assertEqual(r["observed_processes"]["comfyui"]["netns"],
                             r["observed_processes"]["mcp"]["netns"])

    def test_real_kernel_reuseport_second_process_detected(self):
        with ExitStack() as s:
            comfy = s.enter_context(child_listener())
            mcp = s.enter_context(child_listener())
            intruder = s.enter_context(child_listener(comfy["port"]))
            self.assertNotEqual(comfy["pid"], intruder["pid"])
            self.assertEqual(comfy["port"], intruder["port"])
            r = self.observe(comfy, mcp)
            self.assert_deny(r)
            self.assertEqual(r["assessment"], "BLOCKER")
            self.assertIn("COMFYUI_NAMESPACE_OTHER_FD_LISTENER_ON_EXPECTED_PORT", r["blockers"])
            p = r["observed_processes"]["comfyui"]
            self.assertEqual(p["namespace_extra_listener_count_on_expected_port"], 1)
            self.assertEqual(p["namespace_extra_listener_endpoints_on_expected_port"],
                             [{"bind_ip": "127.0.0.1", "port": comfy["port"]}])

    def test_real_kernel_reuseport_second_mcp_listener_detected(self):
        with ExitStack() as s:
            comfy = s.enter_context(child_listener())
            mcp = s.enter_context(child_listener())
            intruder = s.enter_context(child_listener(mcp["port"]))
            self.assertEqual(mcp["port"], intruder["port"])
            r = self.observe(comfy, mcp)
            self.assert_deny(r)
            self.assertIn("MCP_NAMESPACE_OTHER_FD_LISTENER_ON_EXPECTED_PORT", r["blockers"])
            self.assertNotIn("COMFYUI_NAMESPACE_OTHER_FD_LISTENER_ON_EXPECTED_PORT", r["blockers"])

    def test_real_kernel_pid_disappears_fail_closed(self):
        with child_listener() as temporary:
            stopped_pid, port = temporary["pid"], temporary["port"]
        # PID might hypothetically be reused; a positive result never grants
        # execution, so the test's expectation is only that it must deny.
        if Path(f"/proc/{stopped_pid}").exists():
            self.skipTest("PID reused during real-kernel test")
        with child_listener() as alive:
            r = collect_snapshot("synthetic-local-kernel", stopped_pid, alive["pid"],
                                 port, alive["port"])
            self.assert_deny(r)
            self.assertIn("COMFYUI_PROC_OBSERVATION_INCOMPLETE", r["blockers"])


if __name__ == "__main__":
    unittest.main()
