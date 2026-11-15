# SUPERFLUID M086 — owner-local ComfyUI listener observer

**Status: READ-ONLY EVIDENCE, NOT ADMISSION. Production NO-GO. No merge.**

## Scope and reason

M085 proved a structural *negative* gate only. M086 adds a small Linux-only, standard-library observer for an **owner-controlled machine**, to gather an actual `/proc` snapshot without contacting ComfyUI or sending probes. This is **not** the FaceFusion P6 bridge and does not resolve the unverified GPU host.

The observer reads only the **two explicit PIDs** supplied by the operator. It correlates their `/proc/<pid>/fd` socket inodes with `/proc/<pid>/net/tcp` and `tcp6` LISTEN rows, reads netns symlinks and process start ticks before and after, and reports expected listener addresses/ports. Missing permissions, truncated `/proc` data, invalid PIDs, process replacement, wildcard listeners or extra bound ports all fail closed. It does not enumerate arbitrary processes or perform TCP calls, HTTP requests, Docker commands, root escalation, shell subprocesses, GPU calls, model installs or any inference.

### Operator-only example — do not run on a production machine without explicit approval

Review the **exact source** and identify real running PIDs independently; do not guess them. The following is a *template with placeholders*, not a command to copy unchanged:

```bash
umask 077
python3 superfluid_host_observer.py \
  --host-label APPROVED_HOST \
  --comfyui-pid COMFYUI_PID --mcp-pid MCP_PID \
  --comfyui-port 8188 --mcp-port 9000 \
  --output /path/to/private/Delegations/SUPERFLUID_M086_OBSERVATION_UTC.json
```

The observer deliberately does **not** choose or discover PIDs, access the original code checkout, or export automatically. Exit code `2` **always means DENY**, even with a syntactically complete observation. The output is exclusive-create (`O_EXCL`, 0600), never overwrites an existing file or symlink, and prints a minimal one-line status. Do **not** use `sudo` merely to bypass normal visibility failures; the incomplete record itself is a blocker requiring owner review.

Keep reports private: they include PIDs, start ticks, bind IPs/ports, namespace identifiers and user-supplied host label. They intentionally **exclude** command line, environment, credentials, home directory, GPU telemetry, process memory, model inventory, image data and personal media.

## Data and trust boundary

Output schema: `superfluid.host-proc-snapshot.v1`, with `status=DENY`, `assessment=UNVERIFIED|BLOCKER`, `host_isolation_proven=false`, and `execution_authorized=false`. Process roles and host label are **claims provided by the operator**. A snapshot is vulnerable to local compromise, concurrent changes, and omitted forwarding routes. It is **not** cryptographically signed, independently sourced or an M085 `superfluid.host-isolation-observation.v1` attestation; do not rename its schema to impersonate that record. Sharing a netns with the MCP process also does not necessarily mean the system is isolated.

The observer cannot prove that host users, same-netns peers, bridge networks, privileged agents, tunnels, VPN overlays, published container ports, reverse proxies, or any other unobserved caller are unable to hit ComfyUI `/prompt`. It does not inspect nftables/iptables, firewall rules, proxy configs, container port exposure, process rights or container escape protections. **Loopback is not a security boundary against same-namespace code.**

## Offline acceptance

1. Run `python3 -m unittest discover -s tests -p 'test_superfluid_host_observer.py' -v` in a fresh standard-library Python environment (no ComfyUI, GPU or network required).
2. Ensure clean fixtures remain `DENY / UNVERIFIED`, wildcard binds return a blocker, and interrupted PID/ns/file observation never yields `ALLOW`.
3. Compare exact source SHAs to the GitHub review branch and CI record. Keep PR #1 draft and unmerged.
4. An owner-approved host may later create one private report; the next review must establish executable and deployed Git revision separately, inspect firewall/namespaces/forwarders, execute independently authorized negative reachability checks, and develop a signed, one-use execution permit *only as a distinct later phase*.

**No change in production authorization.**
