# SUPERFLUID M100 â file-descriptor-bound read-only workflow catalog

**2026-11-15. Review branch only. Draft PR unmerged. Production NO-GO. Host evidence absent.**

## Reproduced flaw

In M099, `ReadonlyWorkflowCatalog.get_workflow_catalog()` invoked `root.is_symlink()` and then `root.exists()` before `os.scandir(root)`. A local actor with the ability to replace the configured directory pathname could swap a regular directory for a symlink after the check and before the scan. In a synthetic temporary-directory reproduction, this caused the catalog to report `private_secret.json` located outside the configured workflow directory. This is **filename disclosure and a misleading inventory**; the catalog did **not** parse any JSON content or allow execution. Source snapshots and model rights were never attested.

## Fix

- On Linux/POSIX, the catalog now opens its selected directory with `os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | O_CLOEXEC` (when supported). The final path component cannot be a symlink at open time.
- It scans via `os.scandir(directory_fd)`, pinning one opened directory inode even if the pathname is later renamed or replaced. It closes the descriptor in `finally`, including error/limit paths.
- Missing configured directories retain the existing `[]` observation; symlinked roots, inaccessible files, FIFOs or unexpected non-directory inputs yield `None` (tool-level `DENY`). Unsupported platforms without required flags fail closed.
- Per-entry `entry.is_file(follow_symlinks=False)`, safe workflow-ID validation, 500 catalog limit and 2048 directory-entry limit remain. No JSON or sidecar data is loaded. The three-tool MCP allowlist and `superfluid_worker_admission` DENY response remain unchanged.

**Limitation:** `O_NOFOLLOW` guards the **final** configured path component. It does not guarantee that all ancestor path components are nonsymlinks, or stop a same-user attacker from changing filenames inside the opened directory after scan. An actual deployment needs a trusted directory hierarchy, filesystem ownership/perms and/or a reviewed component-by-component `openat` walk, plus independent host containment. The catalog's output is *observed-only* and never evidence of executable workflow safety.

## Tests and reproduction

`tests/test_superfluid_dirfd_catalog.py` adds ten adversarial Linux/synthetic-file tests: final-component symlink denial, directory rename/symlink replacement after fd open, required OS flags, fd closure on errors, missing roots, non-directory files/FIFO denial, symlinked workflow entry denial, no JSON body reads, and catalog limits. The original pre-fix repro is retained in the review package as `RECEIPTS/BASELINE_M099_REPRO.txt`.

Re-run from reviewed source checkout on Linux:

```bash
python3 -m unittest discover -s tests -p 'test_superfluid_*.py' -v
python3 tests/superfluid_protocol_probe.py
python3 tests/superfluid_stdio_probe.py
```

CI should preserve source hash/protocol receipts at an exact commit. These tests use only temporary local directories and synthetic loopback services, never real ComfyUI or GPU.

## External gate

No new authenticated owner-host snapshot, deployed source identity, firewall or `/prompt` reachability proof has been obtained. M097 external-host blocker remains binding. The independent infrastructure v0.21 sidecar check fixes a different SQLite file-integrity problem and does not attest this MCP fork or deployment topology. No merge, paid GPU rental, installation, inference or execution permit.

**Decision: read-only discovery hardening under review; GPU admission DENY; production NO-GO.**
