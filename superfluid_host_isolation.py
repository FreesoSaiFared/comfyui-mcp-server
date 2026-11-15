"""SUPERFLUID offline ComfyUI host-isolation evidence *rejection* gate.

This does not inspect a running host, send packets, authorize /prompt, or validate
the authenticity of operator-supplied observations. An apparently safe record
remains UNVERIFIED and execution is ALWAYS denied.
"""
from __future__ import annotations

import argparse
import ipaddress
import json
import re
from pathlib import Path
from typing import Any

SCHEMA = "superfluid.host-isolation-observation.v1"
_NAMESPACE = re.compile(r"^net:\[[0-9]{1,20}\]$")
_SHA = re.compile(r"^[0-9a-f]{40}$")
_ALLOWED_KEYS = {"schema", "provenance", "observations"}
_EFFECT_CLAIMS = {"permit", "execution_authorized", "approved", "signature", "status"}


def _block(reasons: list[str], unknowns: list[str] | None = None) -> dict:
    return {
        "schema": "superfluid.host-isolation-review.v1",
        "status": "DENY",
        "assessment": "BLOCKER" if reasons else "UNVERIFIED",
        "blockers": sorted(set(reasons)),
        "unverified": sorted(set(unknowns or [])),
        "execution_authorized": False,
        "prompt_submission_allowed": False,
        "host_isolation_proven": False,
        "actual_host_inspected_by_this_tool": False,
    }


def _listener(label: str, item: Any, blockers: list[str]) -> None:
    if not isinstance(item, dict):
        blockers.append(f"{label}_MISSING")
        return
    address, port, netns = item.get("bind_ip"), item.get("port"), item.get("netns")
    if not isinstance(address, str) or address not in {"127.0.0.1", "::1"}:
        blockers.append(f"{label}_NON_LITERAL_LOOPBACK_BIND")
    else:
        try:
            if not ipaddress.ip_address(address).is_loopback:
                blockers.append(f"{label}_NON_LOOPBACK_BIND")
        except ValueError:
            blockers.append(f"{label}_INVALID_BIND")
    if type(port) is not int or not 1 <= port <= 65535:
        blockers.append(f"{label}_INVALID_PORT")
    if not isinstance(netns, str) or _NAMESPACE.fullmatch(netns) is None:
        blockers.append(f"{label}_NAMESPACE_UNOBSERVED")


def assess_host_isolation(record: Any) -> dict:
    """Reject exposed or malformed observations; never return execution approval."""
    blockers: list[str] = []
    unverified: list[str] = [
        "UNSIGNED_OPERATOR_OBSERVATIONS",
        "SAME_NAMESPACE_LOCAL_PROCESS_BYPASS_NOT_EXCLUDED",
        "NEGATIVE_REACHABILITY_NOT_INDEPENDENTLY_ATTESTED",
        "NO_HOST_OWNED_KERNEL_OR_GATEWAY_POLICY_VERIFIED",
    ]
    if not isinstance(record, dict):
        return _block(["INVALID_EVIDENCE_TYPE"], unverified)
    if record.get("schema") != SCHEMA:
        blockers.append("UNKNOWN_SCHEMA")
    if set(record) & _EFFECT_CLAIMS or set(record) - _ALLOWED_KEYS:
        blockers.append("UNEXPECTED_OR_EFFECTFUL_TOP_LEVEL_CLAIM")
    p = record.get("provenance")
    if not isinstance(p, dict):
        blockers.append("MISSING_PROVENANCE")
    else:
        label = p.get("host_label")
        if not isinstance(label, str) or not 1 <= len(label) <= 80 or any(ord(ch) < 32 for ch in label):
            blockers.append("INVALID_HOST_LABEL")
        rev = p.get("deployed_revision")
        if not isinstance(rev, str) or _SHA.fullmatch(rev) is None:
            unverified.append("DEPLOYED_GIT_REVISION_UNVERIFIED")
        # A declared revision is NEVER a cryptographic or runtime attestation.
    obs = record.get("observations")
    if not isinstance(obs, dict):
        return _block(blockers + ["MISSING_OBSERVATIONS"], unverified)
    expected = {"comfyui_listener", "mcp_listener", "comfyui_ingress_bridges", "untrusted_reachability"}
    if set(obs) != expected:
        blockers.append("INCOMPLETE_OR_UNEXPECTED_OBSERVATIONS")
    _listener("COMFYUI", obs.get("comfyui_listener"), blockers)
    _listener("MCP", obs.get("mcp_listener"), blockers)
    comfy = obs.get("comfyui_listener")
    mcp = obs.get("mcp_listener")
    if isinstance(comfy, dict) and isinstance(mcp, dict):
        if comfy.get("port") == mcp.get("port") and comfy.get("netns") == mcp.get("netns"):
            blockers.append("MCP_COMFYUI_PORT_COLLISION")
    bridges = obs.get("comfyui_ingress_bridges")
    if not isinstance(bridges, list):
        blockers.append("UNKNOWN_INGRESS_BRIDGES")
    elif bridges:
        # Includes published container ports, forwarding proxies, tunnels, host
        # networking, and unknown reverse-proxy routes until individually reviewed.
        blockers.append("COMFYUI_INGRESS_BRIDGE_PRESENT")
    probes = obs.get("untrusted_reachability")
    if not isinstance(probes, list):
        blockers.append("MISSING_REACHABILITY_RECORD")
    elif not probes:
        unverified.append("NO_UNTRUSTED_PRINCIPAL_PROBES")
    else:
        seen = set()
        for probe in probes:
            if not isinstance(probe, dict):
                blockers.append("MALFORMED_REACHABILITY_RECORD")
                continue
            principal = probe.get("principal_id")
            reachable = probe.get("tcp_connects")
            if not isinstance(principal, str) or not re.fullmatch(r"[A-Za-z0-9_-]{1,80}", principal):
                blockers.append("INVALID_PRINCIPAL_ID")
            elif principal in seen:
                blockers.append("DUPLICATE_PRINCIPAL_ID")
            else:
                seen.add(principal)
            if type(reachable) is not bool:
                blockers.append("MISSING_TCP_RESULT")
            elif reachable:
                blockers.append("UNTRUSTED_PRINCIPAL_CAN_REACH_COMFYUI")
    return _block(blockers, unverified)


def _no_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("DUPLICATE_JSON_KEY")
        result[key] = value
    return result


def main() -> int:
    parser = argparse.ArgumentParser(description="Offline deny-only SUPERFLUID topology review")
    parser.add_argument("evidence_json", type=Path, help="Operator-supplied JSON; no live host access")
    args = parser.parse_args()
    try:
        path = args.evidence_json
        if path.is_symlink():
            raise ValueError("SYMLINK_INPUT_FORBIDDEN")
        if path.stat().st_size > 262144:
            raise ValueError("EVIDENCE_TOO_LARGE")
        record = json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=_no_duplicate_keys)
        result = assess_host_isolation(record)
    except (OSError, UnicodeError, ValueError, RecursionError) as exc:
        result = _block(["INVALID_EVIDENCE_FILE"])
    print(json.dumps(result, sort_keys=True, indent=2))
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
