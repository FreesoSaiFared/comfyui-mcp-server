"""Host-isolation negative-evidence gate tests: synthetic only, no sockets or GPU."""
from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import unittest
from copy import deepcopy
from pathlib import Path

from superfluid_host_isolation import SCHEMA, assess_host_isolation


def sample() -> dict:
    return {
        "schema": SCHEMA,
        "provenance": {
            "host_label": "synthetic-host",
            "deployed_revision": "a" * 40,
        },
        "observations": {
            "comfyui_listener": {
                "bind_ip": "127.0.0.1", "port": 8188, "netns": "net:[4026531993]"
            },
            "mcp_listener": {
                "bind_ip": "127.0.0.1", "port": 9000, "netns": "net:[4026531993]"
            },
            "comfyui_ingress_bridges": [],
            "untrusted_reachability": [
                {"principal_id": "outside-container", "tcp_connects": False}
            ],
        },
    }


class HostIsolationGateTests(unittest.TestCase):
    def assert_denied(self, data, blocker=None):
        result = assess_host_isolation(data)
        self.assertEqual(result["status"], "DENY")
        self.assertFalse(result["execution_authorized"])
        self.assertFalse(result["prompt_submission_allowed"])
        self.assertFalse(result["host_isolation_proven"])
        self.assertFalse(result["actual_host_inspected_by_this_tool"])
        if blocker:
            self.assertIn(blocker, result["blockers"])
        return result

    def test_apparently_safe_topology_is_still_unverified(self):
        r = self.assert_denied(sample())
        self.assertEqual(r["assessment"], "UNVERIFIED")
        self.assertEqual(r["blockers"], [])
        self.assertIn("SAME_NAMESPACE_LOCAL_PROCESS_BYPASS_NOT_EXCLUDED", r["unverified"])

    def test_ipv6_literal_loopback_still_not_a_permit(self):
        data = sample()
        data["observations"]["comfyui_listener"]["bind_ip"] = "::1"
        self.assertEqual(self.assert_denied(data)["assessment"], "UNVERIFIED")

    def test_ipv4_wildcard(self):
        data = sample()
        data["observations"]["comfyui_listener"]["bind_ip"] = "0.0.0.0"
        self.assert_denied(data, "COMFYUI_NON_LITERAL_LOOPBACK_BIND")

    def test_ipv6_wildcard(self):
        data = sample()
        data["observations"]["comfyui_listener"]["bind_ip"] = "::"
        self.assert_denied(data, "COMFYUI_NON_LITERAL_LOOPBACK_BIND")

    def test_ipv4_alternate_loopback_not_accepted(self):
        data = sample()
        data["observations"]["comfyui_listener"]["bind_ip"] = "127.0.0.2"
        self.assert_denied(data, "COMFYUI_NON_LITERAL_LOOPBACK_BIND")

    def test_rfc1918_bind_not_accepted(self):
        data = sample()
        data["observations"]["comfyui_listener"]["bind_ip"] = "192.168.1.5"
        self.assert_denied(data, "COMFYUI_NON_LITERAL_LOOPBACK_BIND")

    def test_mcp_external_bind(self):
        data = sample()
        data["observations"]["mcp_listener"]["bind_ip"] = "0.0.0.0"
        self.assert_denied(data, "MCP_NON_LITERAL_LOOPBACK_BIND")

    def test_published_port_is_a_blocker_even_with_loopback_comfy(self):
        data = sample()
        data["observations"]["comfyui_ingress_bridges"] = ["docker-publish-8188"]
        self.assert_denied(data, "COMFYUI_INGRESS_BRIDGE_PRESENT")

    def test_remote_reachable_principal(self):
        data = sample()
        data["observations"]["untrusted_reachability"][0]["tcp_connects"] = True
        self.assert_denied(data, "UNTRUSTED_PRINCIPAL_CAN_REACH_COMFYUI")

    def test_unknown_connectivity_is_not_false(self):
        data = sample()
        data["observations"]["untrusted_reachability"][0]["tcp_connects"] = None
        self.assert_denied(data, "MISSING_TCP_RESULT")

    def test_no_connectivity_tests_not_proof(self):
        data = sample()
        data["observations"]["untrusted_reachability"] = []
        r = self.assert_denied(data)
        self.assertIn("NO_UNTRUSTED_PRINCIPAL_PROBES", r["unverified"])

    def test_bool_port_rejected(self):
        data = sample()
        data["observations"]["comfyui_listener"]["port"] = True
        self.assert_denied(data, "COMFYUI_INVALID_PORT")

    def test_string_port_rejected(self):
        data = sample()
        data["observations"]["comfyui_listener"]["port"] = "8188"
        self.assert_denied(data, "COMFYUI_INVALID_PORT")

    def test_missing_namespace_rejected(self):
        data = sample()
        del data["observations"]["comfyui_listener"]["netns"]
        self.assert_denied(data, "COMFYUI_NAMESPACE_UNOBSERVED")

    def test_unknown_schema_rejected(self):
        data = sample()
        data["schema"] = "superfluid.unknown"
        self.assert_denied(data, "UNKNOWN_SCHEMA")

    def test_forged_approval_not_passed_through(self):
        data = sample()
        data["execution_authorized"] = True
        self.assert_denied(data, "UNEXPECTED_OR_EFFECTFUL_TOP_LEVEL_CLAIM")

    def test_duplicate_principal_ids_rejected(self):
        data = sample()
        data["observations"]["untrusted_reachability"] *= 2
        self.assert_denied(data, "DUPLICATE_PRINCIPAL_ID")

    def test_port_collision(self):
        data = sample()
        data["observations"]["mcp_listener"]["port"] = 8188
        self.assert_denied(data, "MCP_COMFYUI_PORT_COLLISION")

    def test_invalid_evidence_type(self):
        self.assert_denied(["not", "a", "record"], "INVALID_EVIDENCE_TYPE")

    def test_missing_observations(self):
        data = sample()
        del data["observations"]
        self.assert_denied(data, "MISSING_OBSERVATIONS")

    def test_missing_revision_remains_unverified(self):
        data = sample()
        data["provenance"]["deployed_revision"] = None
        r = self.assert_denied(data)
        self.assertIn("DEPLOYED_GIT_REVISION_UNVERIFIED", r["unverified"])

    def test_cli_rejects_duplicate_json_keys_without_echoing_input(self):
        script = Path(__file__).resolve().parent.parent / "superfluid_host_isolation.py"
        with tempfile.TemporaryDirectory() as temp:
            src = Path(temp) / "ambiguous.json"
            src.write_text('{"schema":"one","schema":"two"}', encoding="utf-8")
            p = subprocess.run([sys.executable, str(script), str(src)],
                               capture_output=True, text=True, timeout=10)
            self.assertEqual(p.returncode, 2)
            parsed = json.loads(p.stdout)
            self.assertIn("INVALID_EVIDENCE_FILE", parsed["blockers"])
            self.assertNotIn("one", p.stdout)


if __name__ == "__main__":
    unittest.main()
