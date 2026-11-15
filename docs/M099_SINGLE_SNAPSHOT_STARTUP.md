# SUPERFLUID M099 — one bounded read-only startup observation

**Review-only, PR draft/unmerged, production NO-GO. No actual GPU host inspected.**

## Confirmed gap

Through M098, `server.py` performed a guarded `CheckpointLoaderSimple` GET to check availability, then constructed `ReadonlyComfyUIClient` which issued a *second* guarded GET for inventory. Both replies were potentially different: an endpoint could return a benign successful preflight response and substitute different model metadata on the second request. The two complete-transaction deadlines also applied separately. With initial failure, the generic startup retried up to five times with exponential sleep backoff (not a single four-second startup budget).

This is a discovery consistency/availability defect, not a demonstrated execution-authority bypass: inventory always remained untrusted, worker admission always DENY.

## M099 change

- **Read-only startup now makes one guarded GET** under the M098 full HTTP transaction deadline, validates the `CheckpointLoaderSimple` object, and constructs `ReadonlyComfyUIClient.from_observed_payload(...)` from that same single decoded response. No second request, response-swap opportunity, or additional network exposure during the initial inventory snapshot.
- If the initial one-shot observation is invalid, timed out or unavailable, read-only startup exits with `READONLY_DISCOVERY_UNAVAILABLE` and no retry or backoff. **Behavioral trade-off:** a transiently unavailable ComfyUI requires explicit server restart. This is intentional for fail-closed initial discovery.
- The **legacy** mode retains its former availability retries, full client, and explicit unsafe risk acknowledgement; M099 does not grant it production permission.
- Direct standalone `ReadonlyComfyUIClient(url)` still performs a guarded discovery GET for explicit external callers and existing transport tests. `from_observed_payload` is only a way to reuse a supplied untrusted observation, not an attestation API. The allowlist remains `list_models`, `list_workflows`, `superfluid_worker_admission`. No POST or model execution code is introduced.

## Adversarial acceptance

The M099 source-only tests include a local stub returning *different checkpoint lists on successive GETs*. The actual `server.py` subprocess must return only first-response names and show **exactly one GET**. Malformed and 503 responses must fail with no retry, no POST and no tool-serving startup. The tests also exercise snapshot validation, path rejection, malformed nested lists and preservation of no model/rights execution claims. The M091 import-fence test's prior two-GET expectation is updated to one. Re-run all inherited real MCP SDK v1 HTTP/stdio protocol probes, with zero synthetic-backend POSTs, under the exact branch head.

## Limitations

The returned snapshot is **a point-in-time untrusted name list**. It is not authenticated process identity, actual model hashes, file presence, rights, device integrity or host isolation. Between initial discovery and the user reading names, the underlying ComfyUI process could change. A separate host/network gate must still prove direct `/prompt` containment for unauthorized principals. Source tests do not substitute for authorized observation of owner hosts R720/i9ES. No GPU task, paid rental, model download, production deployment, or PR merge.
