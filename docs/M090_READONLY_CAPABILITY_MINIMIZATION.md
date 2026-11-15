# SUPERFLUID M090 — remove inherited read-only execution capabilities

**Review-only. Production NO-GO. PR #1 draft/unmerged. No GPU host inspected.**

## Problem demonstrated by source review

Before M090 the supposedly read-only `ReadonlyComfyUIClient` **subclassed** the effectful `ComfyUIClient`. It overrode three obvious effectful entrypoints but inherited all other methods, including unreviewed future API additions. Separately, `server.py` instantiated the full `WorkflowManager` even in read-only mode; its initialization parsed entire `*.json` workflow templates, and its catalog loader followed local JSON/metadata file paths. Neither was necessary for the only two discovery fields exposed by the read-only tool surface.

The three-tool MCP allowlist already refused direct execution, so this is **defense-in-depth and capability minimization**, not evidence an external caller could already submit a prompt.

## Code contract

- `ReadonlyComfyUIClient` is now a standalone class with only `base_url` and `available_models` instance slots. It inherits **no** API from `ComfyUIClient`. The prior explicitly denied `_queue_workflow`, `run_custom_workflow`, and `cancel_prompt` methods remain solely as compatibility errors; they never POST. Discovery remains literal loopback with proxies/redirects disabled.
- The read-only startup constructs `ReadonlyWorkflowCatalog` rather than `WorkflowManager`. The catalog scans at most **2048 directory entries**, considers at most **500** regular `*.json` filenames, rejects symlinked roots and JSON files, rejects invalid workflow IDs, ignores `*.meta.json`, and **never reads JSON file contents or sidecar metadata**. Filesystem errors and over-limit directories yield a `DENY` tool response. Missing directories produce empty observed inventory.
- **Behavioral trade-off:** the read-only `list_workflows` names now derive from validated filenames, not optional sidecar display names. They are *unverified filename observations*, not proof that JSON is parseable or that the workflow runs. This loses optional friendly labels to reduce parser attack surface.
- Legacy mode keeps its previous `WorkflowManager` and full `ComfyUIClient`; using it still requires the unsafe legacy acknowledgement and is **not** production-authorized.
- MCP `list_models`, `list_workflows`, and `superfluid_worker_admission` remain the only read-only registered tools. Admission always `DENY`; no one-use execute permit is implemented.

## Tests

`tests/test_superfluid_capability_fence.py` adds independent stdlib adversarial tests for inheritance removal, blocked explicit methods, huge/malformed workflow JSON, metadata sidecar non-reading, symlink traversal denial, invalid names, enumeration bounds, and filesystem errors. The pre-existing real server registration test now asserts that `WorkflowManager` is not instantiated in read-only mode.

Run in a reviewed test checkout with compatible SDK v1 dependencies:

```bash
python3 -m unittest discover -s tests -p 'test_superfluid_*.py' -v
python3 tests/superfluid_protocol_probe.py
python3 tests/superfluid_stdio_probe.py
```

Only the two protocol probes talk to their **ephemeral local loopback stubs**, not an owner GPU worker.

## Unresolved boundary

This code cannot stop a same-host process or alternate client from directly reaching ComfyUI `/prompt`. Network namespaces, firewall, container published ports, proxies, tunnels, actual host executable and deployed revision, principal reachability, model rights, and execution permits remain **unknown**. M086–M088 host observer and M089 stdio fix are retained; neither is promoted into production evidence. The owner-host receipt is still missing.

**Decision: no merge, no production, no model installs, no paid rental and no GPU inference.**
