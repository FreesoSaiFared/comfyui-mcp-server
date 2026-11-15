# SUPERFLUID M085 — Host-isolation contract (review-only)

Status: **PRODUCTION NO-GO**. This is a design/evidence artifact for draft PR #1, not deployment instructions that grant authority. Inherited M083/M084 controls remain unchanged.

## Invariant

An MCP read-only allowlist cannot prevent another process from reaching ComfyUI directly on `/prompt`. A loopback-only MCP listener also does **not** isolate ComfyUI's listener. Local users, containers sharing a network namespace, host-network processes, reverse proxies, Docker/Podman published ports, SSH tunnels, ingress controllers, and privileged host administrators are separate bypass surfaces.

**A stage nonce, URL validation, model filename, successful GET, successful CI, TCP refusal from a single location, or legacy risk acknowledgement is never an execute permit.** `SUPERFLUID_MODE=legacy` is intentionally unsafe; the acknowledgement exists to prevent accidental activation, not to authorize work.

## Deployment containment target

1. Default-deny the actual GPU worker at deployment, including its ComfyUI HTTP server and any alternative API/WebSocket/custom-node routes. Do **not** publish the ComfyUI port or use `--listen 0.0.0.0` on an untrusted interface.
2. Prefer a dedicated network namespace or comparably enforced network boundary: ComfyUI plus a *separately audited* trusted broker only. An ordinary untrusted process must not share the namespace or obtain a direct route. Loopback address alone does not make an authorization boundary.
3. Any deliberately exposed ingress must terminate at a gateway enforcing request identity, explicit scope, one-use operator-approved execution permit, replay checks, byte/graph rights and device constraints before any effect. Until that gateway exists, do not expose an execution route.
4. A privileged host principal or attacker with control over process startup, network namespace or firewall can bypass these controls. Host root/trusted administrator governance remains outside the security guarantee.
5. Verify process ownership, container networking, namespace IDs, host and container firewall/nftables rules, forwarding/sidecars, `--network=host` and port publishing against the **real deployed host**. Record a sanitized, immutable receipt; do not infer live deployment from GitHub repository access.
6. Test negative reachability from **each distinct untrusted principal class**, including host user, same-host container, adjacent namespace, LAN/overlay, SSH-forwarding surface, and any ingress proxy. A TCP-only negative probe shows a particular connection failed at that moment; it does not prove permanent enforcement or request-level `/prompt` denial.
7. Review effectful routes beyond `/prompt` (queue deletion, interrupt, frees, uploads, custom endpoints) and ensure the gateway and runtime isolate each reachable effect. No real prompt, installation, paid GPU or model download is permitted in this stage.

## Offline evidence review — NOT a host scan

`superfluid_host_isolation.py` accepts **operator-supplied untrusted** JSON. It opens a local JSON file (maximum 256 KiB), performs structural rejection checks, and prints a diagnostic. It does not call `ss`, `nft`, ComfyUI, GitHub, the network or GPU. Exit code is **always 2**, even when no structural blocker is found.

Example *synthetic only*:

```json
{
  "schema": "superfluid.host-isolation-observation.v1",
  "provenance": {"host_label": "synthetic-host", "deployed_revision": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},
  "observations": {
    "comfyui_listener": {"bind_ip": "127.0.0.1", "port": 8188, "netns": "net:[4026531993]"},
    "mcp_listener": {"bind_ip": "127.0.0.1", "port": 9000, "netns": "net:[4026531993]"},
    "comfyui_ingress_bridges": [],
    "untrusted_reachability": [
      {"principal_id": "untrusted-container", "tcp_connects": false}
    ]
  }
}
```

Run offline: `python3 superfluid_host_isolation.py evidence.json`; expect `status=DENY`, `assessment=UNVERIFIED`, `host_isolation_proven=false`, `execution_authorized=false`. A wildcard bind, ingress bridge, or reachable untrusted principal changes assessment to `BLOCKER`, never to `ALLOW`.

The evaluator deliberately **cannot validate** host origin, container or netfilter configuration, runtime binary identity, a negative probe's provenance, missing attack paths, or signed operator approval. Even forged synthetic "healthy" evidence cannot authorize ComfyUI. It is a negative triage tool, not an attestation verifier.

## Required acceptance on an owner-approved test host (future work)

- Capture host identity and *actual* deployed Git SHA and runtime binary/process identity, not a PR SHA.
- Obtain independent evidence of listening sockets and their network namespaces; review interfaces/forwarding, sidecars and published ports. Protect secrets and internal network details in a private folder.
- Perform a host-owned reachability matrix from each untrusted principal under explicit operator control; separately validate request-level gateway behavior with safe negative requests against a sacrificial stub, not a paid GPU worker.
- Inspect access-control enforcement and prove untrusted processes cannot bypass the broker. Explicitly account for root/admin privileges and local namespace peers.
- Separately implement signed one-time execution authorization, durable atomic dispatch receipts, rights/source-byte/loader/device attestations and human approval. Revalidate at dispatch, not just discovery.
- Have an independent security reviewer sign off before merge, host configuration changes, production, or inference.

## M085 reproducibility

`python3 -m unittest discover -s tests -p 'test_superfluid_*.py' -v` and `python3 tests/superfluid_protocol_probe.py` run only against synthetic fixtures/loopback stubs under reviewed CI. No live-host coverage is implied.

### Scope separation

The Drive P6 `SUPERFLUID__P6_HOST_PROBE_BRIDGE__2026-11-15.py` targets FaceFusion, FFmpeg, ONNX and source frames 82–98. It is **not** ComfyUI network-isolation evidence and must not be substituted for the host-isolation matrix in this PR. The M080 archive-derived GPU registry is likewise not evidence that this MCP fork is installed on the actual GPU host.

**Merge: blocked. Production: NO-GO. Actual host: unverified.**
