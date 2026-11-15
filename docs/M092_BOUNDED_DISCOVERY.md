# SUPERFLUID M092 — bounded ComfyUI read-only discovery

**Review-only; production NO-GO; PR #1 draft/unmerged; no GPU host inspected.**

## Defect

The previous readonly `superfluid_safe_comfy.py` called `requests.Session.get` with the default buffered-response behavior, then `response.json()` in **both** startup preflight and model discovery. A cooperating or hostile loopback service could return a huge (including compressed) response and force unbounded buffering, decoding and JSON parsing before inventory validation. Literal loopback, disabled proxies and redirect denial do not bound the size of untrusted response bytes.

## Patch

Both code paths now use the same small `_read_discovery_payload` helper.

- Literal `127.0.0.1` or `::1` URL validation is retained, with no arbitrary path/userinfo.
- A fresh `requests.Session` sets `trust_env=False`; request is GET only with `allow_redirects=False`, `stream=True`, connect/read timeouts (3s,5s), and `Accept-Encoding: identity`. Even if the responder ignores identity and sends gzip, `iter_content` yields decoded bytes.
- `MAX_DISCOVERY_BYTES=262144` (256 KiB) caps accumulated **decoded** bytes, not merely `Content-Length` or wire/compressed bytes. At most 8192 bytes are requested per iteration. Rejects a reported length above the cap or malformed/absurdly long length, and checks the actual received total regardless of advertised length.
- The JSON decoder receives at most the cap; malformed, nested-too-deep, invalid UTF-8, non-object or unsuccessful HTTP responses result in preflight `False` / model-list `[]` with no execution authority.
- Streaming responses, sessions and connections are closed on rejection. No POST, model installation, queue alteration, cancellation or GPU operation is exposed.

**Compatibility:** a single CheckpointLoaderSimple object-info response whose **decoded JSON body exceeds 256 KiB** is no longer discoverable in readonly mode. That is a deliberate fail-closed resource budget, not proof no checkpoint files exist. The MCP `model_inventory` still enforces path/name/count constraints; names are untrusted metadata and never execution grants.

## Adversarial evidence

`tests/test_superfluid_discovery_bounds.py` exercises synthetic ephemeral loopback responses: small valid JSON, exact 256 KiB ceiling, oversized declared and undeclared bodies, giant/malformed Content-Length, tiny-wire compressed oversized JSON, valid gzip, malformed/deep/non-object JSON, incorrect shape, redirects, and short misleading headers. It asserts zero POST and no proxy routing. Previous MCP HTTP and stdio synthetic probes must still pass. CI saves the exact Git SHA, tests, stdout protocol receipts and source hashes.

**Residual risks:** timeout values apply per network operation and do not constitute a complete wall-clock budget against a deliberately slow-dripping local service. A compromised runtime or other same-host client can directly access ComfyUI independently; this read-only resource guard is **not** a firewall or OS-level isolation. No independently verified deployed host, firewall, network namespace, process identity, principal-reachability matrix, rights grants or signed one-use execution permit exists.

**Decision:** keep the PR draft and unmerged. No actual GPU inference, paid rental, production changes or model downloads.
