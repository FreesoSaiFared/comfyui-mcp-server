# SUPERFLUID M091 — import-time least-authority boundary

**Status:** review only · PR #1 draft/unmerged · GPU admission DENY · production NO-GO.

## Source finding

In M090 the MCP tool allowlist was minimal and its read-only ComfyUI client no longer inherited the effectful client. However, `server.py` still imported `comfyui_client`, all four legacy managers, and six effectful tool-registration modules at module initialization **before** checking `SUPERFLUID_MODE`. Import-time code and transitive dependencies were therefore unnecessarily included in the read-only trusted computing base. This was a code-structure risk, **not** evidence that an MCP caller could submit a workflow.

## M091 change

- Keep FastMCP, logging, the standalone `superfluid_safe_comfy` discovery client, and read-only catalog available.
- Move eleven legacy-only import declarations into a single `if SUPERFLUID_MODE == "legacy":` block **after** the existing `SUPERFLUID_UNSAFE_LEGACY_ACK` check and before their original use.
- Unknown modes or unacknowledged legacy mode terminate without importing effectful project modules. Acknowledged legacy still retains the original effectful modules, tool registration, and separate risk exposure; the acknowledgment is **not an execution permit**.
- No change to three registered read-only MCP tools, no network isolation, no ComfyUI server configuration, no GPU invocation or model download.

## Executed acceptance contract

`tests/test_superfluid_import_fence.py` runs `server.py` in a **fresh Python subprocess**, inserting a `MetaPathFinder` that rejects imports of the effectful project client, legacy managers and tool modules. With a synthetic ephemeral `127.0.0.1` backend, default/explicit read-only startup must complete, expose exactly `list_models`, `list_workflows`, `superfluid_worker_admission`, report `DENY`, and produce zero ComfyUI POST. It also confirms invalid mode and unacknowledged legacy fail **before** effectful imports, while explicitly acknowledged legacy attempts the separate effectful import path and is stopped by the test finder before any network activity.

Retain existing SDK v1 real HTTP and stdio end-to-end protocol probes. Preserve their logs, complete source hash inventory and exact Git commit in CI evidence. The module import guard is a **test assertion**, not a sandbox or runtime security manager. It is not an import policy against hostile Python code executing within the same process.

## Persistent limitations and next action

Direct ComfyUI `/prompt` remains unprotected by this repo change if a local process, tunnel, proxy, published port or remote actor can reach ComfyUI itself. No owner-approved, authenticated snapshot of an actual GPU host exists in the checked Delegations results; runtime identity, firewall/network policy, principal reachability, rights, and signed one-use dispatch are unverified. No tests in this milestone access the actual owner server.

**Decision: keep PR draft/unmerged; production NO-GO; no model installations, GPU inference or paid rentals.**
