# SUPERFLUID M101 — ancestor-fd-pinned workflow catalog (review only)

Date: 2026-11-15. Scope: owner-controlled draft PR #1, read-only discovery
only. This patch does NOT prove a deployed GPU worker, network isolation,
model rights, workflow execution safety, or authorization. **Production NO-GO.**

## M100 residual issue

M100 opened the configured workflow directory with `O_NOFOLLOW` and
`O_DIRECTORY`, so the final directory pathname could not be a symlink.
However, a *parent* component could still be a symlink, and a local
path-replacement actor could substitute an ancestor between path construction
and the single final `open`. A metadata-only inventory could then report
filenames from an unintended directory. No JSON body, model or prompt was
accessed. This is a **filename confidentiality/integrity** concern, not an
observed command-execution bypass.

## M101 review patch

- Walk absolute paths starting from an opened `/` directory fd, or relative
  paths from a pinned `.` directory fd.
- Open each remaining component individually using `os.open(component,
  O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC, dir_fd=parent_fd)`.
- Close each old directory fd after opening the next, retain only the final
  pinned directory inode for `os.scandir(fd)`, and close it on normal,
  early-return and error paths.
- Reject `..`, path depth over 64 components, unsupported `dir_fd` and
  required-flag platforms; fail closed on permission/symlink/non-directory
  errors.
- Keep M100's missing-directory observed-empty `[]` behavior, bounded
  enumeration (2048 entries, 500 workflows), no JSON/sidecar parsing,
  no model-content inspection and always-DENY admission.

## Adversarial acceptance

New tests: `tests/test_superfluid_ancestor_dirfd.py` (10 cases), including:
existing ancestor symlink; swapping an ancestor after its fd is pinned;
`O_NOFOLLOW` and `dir_fd` on every component; parent traversal and excessive
depth; absent nested directory; injected intermediate permission error with
fd cleanup; unsupported platform; relative paths; no workflow JSON read.

Existing M100 test `test_open_uses_directory_and_no_follow_flags` is updated
to expect *multiple* component opens, each using the required flags; all other
M100 tests remain in place. CI executes the complete `test_superfluid_*.py`
suite and both real SDK-v1 MCP transport probes against a synthetic loopback
backend. Exact pass/failure receipts must be reviewed at the final Git commit.

## Explicit remaining limitations

- A trusted executable can still be tricked by a process able to rewrite
  entries *inside* the pinned directory; the catalog enumerates names only.
- Directory ownership and Unix permissions, mount replacement, bind mounts,
  process namespaces and host-root privileges are not attested here.
- `O_NOFOLLOW` per component addresses symbolic links and pathname races,
  **not** arbitrary mount topology or inode modification by a privileged actor.
- No real GPU host, deployed fork SHA, listener, OS firewall or namespace,
  ingress/sidecar, untrusted-principal negative reachability, rights
  attestation or signed single-use execution permit was inspected.
- Read-only MCP hardening alone cannot stop direct ComfyUI `/prompt` or
  other effectful API calls if that separate server is reachable.

## Decision

Remain on draft review branch; do NOT merge, deploy, install, rent, infer,
start a real GPU, submit prompts or enable `SUPERFLUID_MODE=legacy`. Do not
interpret a green synthetic test result as host authorization. Actual
owner-approved host observation and independent OS/network isolation review
are still the next external blocker. **Execution DENY; production NO-GO.**
