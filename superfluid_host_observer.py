"""SUPERFLUID M086 owner-run, READ-ONLY Linux /proc listener snapshot.

Never contacts ComfyUI, creates sockets, changes firewall/networking, scans other
processes, validates rights, or grants execution. PID labels are operator claims.
Only the two explicitly supplied PIDs are inspected. No command line or env reads.
The report contains PIDs, TCP bind addresses/ports, and netns identifiers; keep private.
"""
from __future__ import annotations

import argparse
import ipaddress
import json
import os
import re
from pathlib import Path
from typing import Any

SCHEMA = "superfluid.host-proc-snapshot.v2"
MAX_TCP_BYTES = 1024 * 1024
MAX_FDS = 4096
_NETNS = re.compile(r"^net:\[[0-9]{1,20}\]$")
_SOCKET_INODE = re.compile(r"^socket:\[([0-9]{1,20})\]$")
_UNKNOWN = [
    "UNSIGNED_OWNER_LOCAL_OBSERVATION",
    "PROCESS_PURPOSE_AND_DEPLOYED_GIT_REVISION_NOT_ATTESTED",
    "OTHER_PROCESS_AND_SAME_NAMESPACE_BYPASSES_NOT_EXCLUDED",
    "SHARED_INODE_ACCESS_BY_OTHER_PROCESSES_NOT_EXCLUDED",
    "UNIX_SOCKET_TUNNELS_AND_CROSS_NAMESPACE_PORT_FORWARDING_NOT_INSPECTED",
    "PUBLISHED_PORTS_TUNNELS_FORWARDING_NOT_INSPECTED",
    "KERNEL_NFTABLES_CONTAINER_NETWORK_POLICY_NOT_INSPECTED",
    "INDEPENDENT_UNTRUSTED_PRINCIPAL_REACHABILITY_NOT_TESTED",
    "NO_SIGNED_EXECUTION_PERMIT_OR_OPERATOR_APPROVAL",
]


def _bounded(path: Path, size: int) -> str:
    with path.open("rb") as f:
        data = f.read(size + 1)
    if len(data) > size:
        raise ValueError("INPUT_TOO_LARGE")
    return data.decode("ascii", "strict")


def _start_ticks(path: Path) -> str:
    # /proc/<pid>/stat may contain spaces or ) in the comm field.
    raw = _bounded(path, 16384)
    end = raw.rfind(")")
    if end < 0:
        raise ValueError("INVALID_PROC_STAT")
    fields = raw[end + 1:].split()  # first field after comm is state (field 3)
    if len(fields) < 20 or not fields[19].isdigit():
        raise ValueError("INVALID_PROC_STAT")
    return fields[19]  # starttime, field 22


def _tcp_ip(word: str, v6: bool) -> str:
    if v6:
        if len(word) != 32:
            raise ValueError("INVALID_TCP6_ADDR")
        value = b"".join(bytes.fromhex(word[i:i+8])[::-1] for i in range(0, 32, 8))
        return str(ipaddress.IPv6Address(value))
    if len(word) != 8:
        raise ValueError("INVALID_TCP4_ADDR")
    return str(ipaddress.IPv4Address(bytes.fromhex(word)[::-1]))


def parse_tcp_listeners(data: str, *, ipv6: bool) -> list[dict]:
    """Decode /proc/net/tcp{,6} and preserve only LISTEN rows."""
    lines = data.splitlines()
    if not lines or not lines[0].lstrip().startswith("sl"):
        raise ValueError("INVALID_TCP_HEADER")
    result = []
    for line in lines[1:]:
        cols = line.split()
        if len(cols) < 10:
            raise ValueError("INVALID_TCP_ROW")
        if cols[3] != "0A":
            continue
        addr = cols[1].split(":")
        if len(addr) != 2 or len(addr[1]) != 4 or not cols[9].isdigit():
            raise ValueError("INVALID_TCP_LISTENER")
        port = int(addr[1], 16)
        if port < 1 or port > 65535:
            raise ValueError("INVALID_TCP_PORT")
        result.append({"bind_ip": _tcp_ip(addr[0], ipv6), "port": port,
                       "inode": cols[9]})
    return result


def _snapshot_process(pid: int, proc_root: Path, expected_port: int | None = None) -> dict:
    if type(pid) is not int or pid < 1 or pid > 4194304:
        raise ValueError("INVALID_PID")
    base = proc_root / str(pid)
    start = _start_ticks(base / "stat")
    netns = os.readlink(base / "ns/net")
    if not _NETNS.fullmatch(netns):
        raise ValueError("UNTRUSTED_NETNS_FORMAT")
    fd_dir = base / "fd"
    inodes: set[str] = set()
    with os.scandir(fd_dir) as entries:
        for n, entry in enumerate(entries):
            if n >= MAX_FDS:
                raise ValueError("FD_INVENTORY_TOO_LARGE")
            try:
                link = os.readlink(entry.path)
            except FileNotFoundError:
                # /proc/<pid>/fd changes rapidly. Never treat a partial read as proof.
                raise ValueError("FD_RACED_OR_DISAPPEARED") from None
            match = _SOCKET_INODE.fullmatch(link)
            if match:
                inodes.add(match.group(1))
    candidates = []
    namespace_expected = []
    for filename, is_v6 in [("tcp", False), ("tcp6", True)]:
        rows = parse_tcp_listeners(_bounded(base / "net" / filename, MAX_TCP_BYTES), ipv6=is_v6)
        candidates.extend(x for x in rows if x["inode"] in inodes)
        if expected_port is not None:
            namespace_expected.extend(x for x in rows if x["port"] == expected_port)
    end = _start_ticks(base / "stat")
    netns2 = os.readlink(base / "ns/net")
    if start != end or netns != netns2:
        raise ValueError("PID_IDENTITY_OR_NAMESPACE_CHANGED")
    # A second socket can listen on the same endpoint via SO_REUSEPORT or
    # a namespace proxy. The named process may own one inode while a different
    # process owns another. Compare the namespace table against selected FDs.
    # This detects negative evidence, never proves exclusive ownership (FDs
    # may be shared by other processes; namespace tables can race).
    others = [x for x in namespace_expected if x["inode"] not in inodes]
    other_endpoints = sorted({(x["bind_ip"], x["port"]) for x in others})
    # Exclude socket inodes from receipt (local ephemeral detail).
    listens = sorted({(x["bind_ip"], x["port"]) for x in candidates})
    return {"pid": pid, "start_ticks": start, "netns": netns,
            "tcp_listeners": [{"bind_ip": ip, "port": port} for ip, port in listens],
            "namespace_extra_listener_count_on_expected_port": len(others),
            "namespace_extra_listener_endpoints_on_expected_port": [
                {"bind_ip": ip, "port": port} for ip, port in other_endpoints],
            "socket_fd_count": len(inodes)}


def collect_snapshot(host_label: str, comfyui_pid: int, mcp_pid: int,
                     comfyui_port: int, mcp_port: int, *,
                     proc_root: Path = Path("/proc")) -> dict[str, Any]:
    """Observes only caller-specified processes. Never returns ALLOW."""
    blockers = []
    if comfyui_pid == mcp_pid:
        blockers.append("SAME_PID_FOR_COMFYUI_AND_MCP")
    processes: dict[str, Any] = {}
    if (not isinstance(host_label, str) or not re.fullmatch(r"[A-Za-z0-9_-]{1,64}", host_label)):
        blockers.append("INVALID_HOST_LABEL")
    requested = {"comfyui": comfyui_port, "mcp": mcp_port}
    for key, pid in [("comfyui", comfyui_pid), ("mcp", mcp_pid)]:
        try:
            port = requested[key]
            checked_port = port if type(port) is int and 1 <= port <= 65535 else None
            processes[key] = _snapshot_process(pid, proc_root, expected_port=checked_port)
        except (OSError, ValueError, UnicodeError) as exc:
            # Codes rather than paths or exception text (minimizes private leakage).
            processes[key] = None
            blockers.append(key.upper() + "_PROC_OBSERVATION_INCOMPLETE")
    for key, port in [("comfyui", comfyui_port), ("mcp", mcp_port)]:
        if type(port) is not int or not 1 <= port <= 65535:
            blockers.append(key.upper() + "_INVALID_EXPECTED_PORT")
            continue
        p = processes.get(key)
        if p is None:
            continue
        matched = [x for x in p["tcp_listeners"] if x["port"] == port]
        if not matched:
            blockers.append(key.upper() + "_EXPECTED_LISTENER_NOT_PROVEN")
        for x in matched:
            if x["bind_ip"] not in ("127.0.0.1", "::1"):
                blockers.append(key.upper() + "_NON_LITERAL_LOOPBACK_LISTENER")
        if any(x["port"] != port for x in p["tcp_listeners"]):
            blockers.append(key.upper() + "_ADDITIONAL_TCP_LISTENER_OBSERVED")
        if p["namespace_extra_listener_count_on_expected_port"]:
            blockers.append(key.upper() + "_NAMESPACE_OTHER_FD_LISTENER_ON_EXPECTED_PORT")
    a, b = processes.get("comfyui"), processes.get("mcp")
    if a and b and a["netns"] == b["netns"]:
        # Co-location is not proof of a bypass, but explicitly signals risk.
        unknowns = _UNKNOWN + ["COMFYUI_AND_MCP_SHARE_NETWORK_NAMESPACE"]
    else:
        unknowns = _UNKNOWN + ["PROCESS_NAMESPACE_RELATION_UNVERIFIED"]
    return {"schema": SCHEMA, "status": "DENY",
            "assessment": "BLOCKER" if blockers else "UNVERIFIED",
            "host_label": host_label if isinstance(host_label, str) and len(host_label) <= 64 else "INVALID",
            "observed_processes": processes,
            "blockers": sorted(set(blockers)), "unverified": sorted(set(unknowns)),
            "prompt_submission_allowed": False, "execution_authorized": False,
            "host_isolation_proven": False,
            "authoritative_attestation": False,
            "network_calls_performed": False,
            "gpu_inference_performed": False}


def save_no_overwrite(path: Path, record: dict) -> None:
    """Create exactly one private report. Never overwrite existing files/symlinks."""
    payload = (json.dumps(record, sort_keys=True, indent=2) + "\n").encode("utf-8")
    if len(payload) > 262144:
        raise ValueError("RECEIPT_TOO_LARGE")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    flags |= getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(path, flags, 0o600)
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(payload)
            f.flush()
            os.fsync(f.fileno())
    except BaseException:
        try:
            path.unlink(missing_ok=True)
        except OSError:
            pass
        raise


def main() -> int:
    parser = argparse.ArgumentParser(description="Read-only owner-local ComfyUI/MCP proc listener snapshot")
    parser.add_argument("--host-label", required=True)
    parser.add_argument("--comfyui-pid", type=int, required=True)
    parser.add_argument("--mcp-pid", type=int, required=True)
    parser.add_argument("--comfyui-port", type=int, required=True)
    parser.add_argument("--mcp-port", type=int, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    r = collect_snapshot(args.host_label, args.comfyui_pid, args.mcp_pid,
                         args.comfyui_port, args.mcp_port)
    try:
        save_no_overwrite(args.output, r)
    except (OSError, ValueError):
        print(json.dumps({"status": "DENY", "error": "PRIVATE_RECEIPT_WRITE_FAILED"}))
        return 2
    print(json.dumps({"status": "DENY", "assessment": r["assessment"],
                      "receipt_written": True, "blocker_count": len(r["blockers"])}))
    return 2  # Evidence only; NEVER an execution gate pass


if __name__ == "__main__":
    raise SystemExit(main())
