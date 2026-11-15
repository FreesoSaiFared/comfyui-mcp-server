# SUPERFLUID M088 — actual Linux kernel observer falsification probe

**Scope:** tests run against real local Linux `/proc`, TCP LISTEN sockets, and separate unprivileged subprocesses. **They do not contact any production GPU worker or ComfyUI.** All subprocesses bind ephemeral 127.0.0.1 ports, open no HTTP requests, never accept a connection, do not invoke `nvidia-smi`, and terminate before the test completes.

## Why this is an advance over M087

M087's same-port test uses synthetic files representing `/proc/<pid>/net/tcp` and `/fd/` entries. That is an isolated parser test, not a proof that Linux's socket bookkeeping actually exposes a second `SO_REUSEPORT` listener as a distinct inode under live conditions.

The M088 test `tests/test_superfluid_kernel_observer.py` starts separate Python processes, each with a real TCP listener. It then exercises the **unchanged** M087 `superfluid_host_observer.collect_snapshot()` on their real PIDs. Independent adversarial processes bind the same loopback port with `SO_REUSEPORT`; the observer must detect the extra inode in the namespace table and return `BLOCKER` while still returning `DENY` for all cases.

Test cases:
- two real listener processes with unique loopback ports => `UNVERIFIED` and `DENY`;
- second independent process with `SO_REUSEPORT` on nominated ComfyUI port => `COMFYUI_NAMESPACE_OTHER_FD_LISTENER_ON_EXPECTED_PORT`;
- second process on nominated MCP port => `MCP_NAMESPACE_OTHER_FD_LISTENER_ON_EXPECTED_PORT`;
- terminated PID => observation incomplete, `DENY` (skip if PID reused; never depend on PID reuse for authorization).

## Reproduce safely

Run on a Linux development machine, **not on a GPU production host**:

```bash
cd <trusted-audited-source-tree>
python3 -m unittest discover -s tests -p 'test_superfluid_kernel_observer.py' -v
```

Requires Python stdlib, Linux procfs, local loopback and `SO_REUSEPORT`. Test suite skips on unsupported platforms. It creates only ephemeral loopback listeners; no HTTP traffic or external network required. CI also invokes this through the `test_superfluid_*.py` discovery suite.

## Security boundary / remaining unknowns

A successful test confirms that one concrete runtime socket arrangement is observed correctly. It does NOT establish authoritative ComfyUI process identity, absence of shared FDs, absence of proxying through other ports, isolation of untrusted same-namespace processes, port forwarding, firewall rules, privilege boundaries, or a deployed runtime. It is not a replacement for host-owned observations and a negative reachability matrix.

**Cannot grant execution.** This test never changes `SUPERFLUID_MODE`, writes a dispatch permit, accesses a real GPU, downloads weights, or submits `/prompt`. Read-only control-plane and host separation must be independently reviewed. M087 JSON snapshot schema stays `superfluid.host-proc-snapshot.v2` (no observer API change).

**Decision:** production `NO-GO`, draft PR unmerged. Continue only when operator-owned host evidence is available; do not mistake CI for deployed-host proof.
