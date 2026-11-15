# SUPERFLUID M087 — namespace-wide same-port collision evidence

**Status:** Source-review candidate, **not deployed**. Production **NO-GO**; default admission **DENY**. M083–M086 source histories and Google Drive packages are immutable.

## Problem falsified

M086 confirms the two *nominated* process-owned listener inventories, not all other sockets in their namespaces. A second process can own another LISTEN socket on the same ComfyUI endpoint (for example via SO_REUSEPORT). Checking only sockets referenced by ComfyUI's nominated file descriptors can therefore miss a same-port bypass. M086 properly denied execution anyway, but its diagnostic assessment could have been overly reassuring.

## Exact correction

- `superfluid_host_observer.py`: output schema is now `superfluid.host-proc-snapshot.v2` (M086 used v1).
- For each nominated PID, read **only its namespace's existing `/proc/<pid>/net/tcp` and `tcp6`** tables, as in M086; retain rows for the *operator-nominated expected port*. Compare each namespace listener's socket inode to the selected PID's observed `fd` socket inode set.
- If the namespace table contains a listener on the expected port whose inode is **not referenced by the nominated PID**, add `COMFYUI_NAMESPACE_OTHER_FD_LISTENER_ON_EXPECTED_PORT` or `MCP_NAMESPACE_OTHER_FD_LISTENER_ON_EXPECTED_PORT` to blockers. Expose count and deduplicated bind-address/port pairs, never inode numbers.
- A wildcard or external-address listener owned by the selected process remains blocked by existing M086 checks. An unrelated namespace port is not reported: avoid broad host inventory and needless private-data collection.
- Even if the selected PID owns multiple legitimate inodes or all target-port inodes, return `DENY / UNVERIFIED`—other processes may hold copies of the *same* socket FD. No `/prompt` execution, network probes, subprocess, `sudo`, root access, model reads, image generation, firewall changes or service restarts.
- Retain no-overwrite, private 0600 JSON output. Expect exit code **2 always**; that is a deliberate denial, not a CLI malfunction.

## Synthetic acceptance

Seven new adversarial tests and one schema test (eight added to M086's 26) cover duplicated loopback same port, wildcard same port, IPv6 same port, MCP equivalent, deliberately unrelated port, same-process multiple listening sockets, duplicate same-address inodes and explicit schema version. Full M085+M086+M087 stdlib test set runs **56/56 locally** on Python 3.13 without live host access. Source still requires exact branch CI review.

## Important limits

- `/proc/<pid>/net` is *network-namespace-wide*, but this cannot tell if another process holds the *same* socket inode; or if forwarding/proxies/tunnels exist in other namespaces. It does not scan the process tree or host firewall.
- PID identity remains user/operator claimed, unsigned and unauthenticated; namespace and FD tables can change after the snapshot. A reader with restricted `/proc` permissions might get blockers rather than data.
- This provides **new negative evidence only**. A clean snapshot cannot grant actual-host isolation, registry/model/rights approval, execution permission, or merge readiness. The current deployed GPU host remains unknown until a trusted owner explicitly obtains an observation.
- Even a host with this source deployed still requires independently reviewed isolation, network reachability matrix from untrusted principals, signed one-use execution permit, durable nonce replay prevention, artifact/loader/rights/device checks, and human approval before any GPU work.

## Reproduction without a host

From the repo branch:

```bash
python3 -m unittest discover -s tests -p 'test_superfluid_host_observer.py' -v
python3 -m unittest discover -s tests -p 'test_superfluid_*.py' -v
```

For an eventual authorized, owner-local observation, use the existing M086 operator handoff for discovering the exact ComfyUI and MCP PIDs, command arguments and private output directory. Never guess PIDs and never use an independent test container's `/proc` as a substitute for the GPU host. M087 returns schema v2; preserve any M086 schema-v1 receipts separately.

**Decision:** M087 source scope review only. Production NO-GO. No real worker contacted.
