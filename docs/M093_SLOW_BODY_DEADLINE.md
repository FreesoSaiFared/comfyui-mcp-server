# SUPERFLUID M093 — slow-drip body deadline and compressed wire audit

**Review-only. Production NO-GO. PR #1 stays draft/unmerged. Owner GPU host uninspected.**

## Concrete M092 residual gap

M092 caps the *size* of the decoded CheckpointLoaderSimple response at 256 KiB, but requests/urllib3's 5-second read timeout is a **per-idle-read** timer, not an end-to-end deadline. A malicious local HTTP peer can drip a byte repeatedly within the timeout to keep the response body open. Compression can make this worse: an attacker can prolong the gzip optional-header fields without making the decompressor return decoded bytes.

## M093 patch / deliberately limited guarantee

The same readonly `_read_discovery_payload` path now checks a four-second elapsed-time budget at each received **raw wire byte**, rather than only at an emitted decompressed chunk. Raw TCP delivery is consumed at one byte per iteration to prevent slow, partial decompressor headers from concealing progress. Read-idle timeout is 0.75 seconds; connect timeout is two seconds. Both **compressed wire bytes and decompressed decoded JSON bytes** are separately capped at 256 KiB. Allowed response encodings are identity and gzip only; invalid/truncated/concatenated gzip bodies and unsupported encodings are denied. Proxy trust remains disabled; redirects remain refused.

The original M092 healthy JSON and gzip inventory behavior is retained. A valid discovery taking longer than this local budget will be **unavailable**, not `ALLOW`; models are still unverified filename hints.

**Guarantee boundary:** This is a **body-phase elapsed-time check**, not a strict wall-clock limit for the entire HTTP transaction. Python requests and http.client can spend arbitrarily long processing an intentionally slow-dripped HTTP **header** before yielding control. A raw-byte read may also finish up to one 0.75s idle timeout after the budget has elapsed. Decompression/JSON parsing is bounded by bytes but not a hard CPU-process deadline. A future truly hard complete-transaction timeout needs separate cancellable process isolation or a transport with absolute socket-level deadlines, independently tested. Do not claim the current four-second number is a hard process or network wall-clock SLA.

## Adversarial tests

`tests/test_superfluid_discovery_deadline.py` uses only ephemeral 127.0.0.1 HTTP stubs. Cases include a slowly delivered plain JSON body, a trickling model inventory body, a gzip stream with a long optional filename header that yields no decoded output for a prolonged period, healthy gzip, unsupported encoding, incomplete gzip, extra concatenated gzip, and denied proxy-environment fallback. Slow-body tests lower the deadline within their own test process; no owner host or GPU is accessed. CI also runs all previous M083–M092 synthetic, real-local-kernel, stdio and HTTP MCP protocol tests.

## Operator/security boundary

This milestone does not identify the deployed ComfyUI host, inspect host networking, attest model rights or create signed one-use GPU execution permits. A distinct client with direct `/prompt` reachability remains a deployment-level bypass regardless of discovery time limits. Actual host authentication and OS firewall/network namespace review are still blocked pending owner-provided evidence. No inference, paid rental, production deployment, model installation or PR merge authorized.

**Decision:** maintain read-only MCP discovery, permanent worker-admission DENY, and production NO-GO.
