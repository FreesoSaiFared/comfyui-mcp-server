# SUPERFLUID M098 — complete HTTP transaction deadline

**Review-only. PR #1 remains draft and unmerged. GPU admission DENY; production NO-GO.**

## Falsified M093 assumption

M093 had a four-second body phase budget, checked after `requests.get(..., stream=True)` returned HTTP headers. Requests/urllib3's 750ms *idle* read timeout could be reset by a malicious local peer sending each next HTTP header byte before idle timeout. A controlled 127.0.0.1 test deliberately emitted 92 header bytes slowly; M093's `safe_check_comfyui_available` denied the request but only returned after **7.76 seconds**, exceeding its nominal four-second budget. This is a **latency/availability weakness**, not an observed unauthorized `/prompt` call.

## Correction

M098 changes only the read-only `superfluid_safe_comfy.py` discovery helper. An `httpx.AsyncClient` coroutine now encompasses the full request lifecycle **including connection, response headers, compressed/uncompressed body reads and JSON parsing** inside `asyncio.wait_for(..., timeout=MAX_DISCOVERY_BODY_SECONDS)`. Default budget remains four seconds. Prior name `MAX_DISCOVERY_BODY_SECONDS` is retained for backwards compatibility, but its scope is now transaction-wide. The synchronous constructor/server startup uses `asyncio.run` to execute it, only if no event loop is already running. A caller attempting synchronous discovery *inside* an active loop fails closed with an unavailable inventory, rather than spawning unbounded worker threads.

The same constraints remain: loopback literal only, no environment proxies, no redirects, HTTP GET only, explicit identity/gzip encodings, 256 KiB *compressed-wire* and 256 KiB *decoded JSON* caps, malformed header and gzip rejection, and three read-only MCP tools with denial of effectful calls. `httpx==0.28.1` is explicitly included in requirements for the new direct dependency. It is also transitive in MCP SDK v1, but transitive reliance is insufficient for this source dependency.

## Adversarial acceptance

`tests/test_superfluid_transaction_deadline.py` uses only ephemeral localhost socket stubs to test slow response headers, cumulative header/body delays, model discovery, healthy discovery and calls from an active asyncio event loop. Previous M083–M093 unit, real-local-kernel and MCP HTTP/stdio synthetic protocol tests must still pass in CI with zero synthetic-backend POSTs.

Local reproduction on this isolated testbed showed `asyncio.wait_for` interrupting slow header delivery at a 0.50s test deadline in ~0.502s; the full patch has five local regression tests passing. The exact GitHub branch CI results supersede local results when available.

## Deliberate limits

An asyncio timeout is **cooperative**, not a kernel-enforced or hostile-code-proof hard deadline: OS scheduling stalls, native library bugs, and event-loop blocking code can still extend elapsed time. All HTTP operations remain inside an untrusted local process, and a peer with direct ComfyUI `/prompt` reachability bypasses MCP regardless of this change. Owner-controlled host PIDs, deployed Git revision, effective firewall/network namespaces, external ingress/tunnels, independent principal probes, model rights and signed one-use permits remain unverified. No actual owner host, GPU, paid rental, production deployment or model installation is accessed.

**Decision: retain draft/unmerged PR; execute no GPU jobs; production NO-GO.**
