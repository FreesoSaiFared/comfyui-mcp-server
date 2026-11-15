# SUPERFLUID M089 — MCP stdio control-channel integrity

**Review-only. Production NO-GO. Draft PR #1 must not be merged without operator/security review.**

## Finding

The real owner-controlled `server.py` printed startup banners, connection-health progress and status messages to standard output *before* calling `mcp.run(transport="stdio")`. The MCP stdio transport reserves **stdout for JSON-RPC frames**; human-readable startup output can corrupt initialization. Earlier end-to-end acceptance exercised **Streamable HTTP**, not stdio, so its passing result did not establish stdio compatibility.

## Patch

The server now detects the existing `--stdio` entrypoint before its startup operations and routes **its own** informational `print` calls to **stderr** for that transport. For HTTP, the previous console behavior remains. It deliberately does **not** replace `sys.stdout` or globally redirect stdout, which would also corrupt the SDK's outbound JSON-RPC. No extra effectful tools, ComfyUI routes, API clients or permission mechanisms are registered.

Review change: `server.py` only plus `tests/superfluid_stdio_probe.py`, this document, CI audit. Legacy mode still requires its explicit unsafe acknowledgement and is never authorized for production.

## Acceptance

The new executable protocol probe launches the actual `server.py --stdio` in a child process using the pinned **MCP SDK v1** `StdioServerParameters` and `stdio_client`. Its only backend is an ephemeral stub on **127.0.0.1**. Successful `ClientSession.initialize` and `list_tools` require valid stdin/stdout protocol framing. The probe requests `list_models`, demands the always-denied worker admission response, attempts an unavailable `run_workflow`, and asserts **zero backend POST**. It uses an empty temporary workflow directory, never installs models, never starts an actual ComfyUI or a GPU, and never contacts an external address.

CI should run both `tests/superfluid_protocol_probe.py` (HTTP) and `tests/superfluid_stdio_probe.py` (stdio), preserve `ACTUAL_MCP_HTTP_PROTOCOL.log` and `ACTUAL_MCP_STDIO_PROTOCOL.log` under the source-revision evidence, and fail the job if either exits nonzero.

Successful tests establish **only** that this fork's current read-only stdio tool surface can handshake and reject effects against a synthetic loopback stub. This is neither deployment-level network isolation nor model or workflow authorization. Host identity, namespace/firewall policy, port exposure, bridge/tunnels, untrusted-principal tests, license/source bytes, signed one-use dispatch permits and real GPU inference remain **unverified and prohibited**.

## Owner-host blocking dependency

M086–M088 observation remains separate from this control-channel repair. Actual operator-approved PIDs and verified runtime identity are still missing; no owner GPU host was inspected by M089. The original M088 evidence package remains immutable.

**Decision: keep PR draft/unmerged, read-only mode default, no generation, paid rentals, installs or production changes.**
