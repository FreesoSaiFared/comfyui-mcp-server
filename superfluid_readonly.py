"""SUPERFLUID read-only ComfyUI MCP admission surface.

Integration branch only. This intentionally exposes NO generation, download,
installation, cancellation, defaults-mutation, or publish tools. Model names are
untrusted inventory hints, never cryptographic identity or GPU admission.
"""
from __future__ import annotations
import os
import re
from pathlib import Path
from typing import Any

MAX_MODELS = 500
MAX_WORKFLOWS = 500
_SAFE_PART = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._ -]{0,199}$")
_SAFE_ID = re.compile(r"^[A-Za-z0-9_-]{1,100}$")


def _safe_model_name(value: Any) -> bool:
    if not isinstance(value, str) or len(value) > 400 or not value:
        return False
    if value.startswith(("/", ".")) or "\\" in value or "%" in value or any(ord(c)<32 for c in value):
        return False
    parts = value.split("/")
    return all(p not in {".", ".."} and _SAFE_PART.fullmatch(p) for p in parts)


def model_inventory(available: Any) -> dict:
    if not isinstance(available, list) or len(available) > MAX_MODELS or not all(_safe_model_name(m) for m in available):
        return {"status": "DENY", "error": "UNTRUSTED_MODEL_INVENTORY", "models": [], "count": 0,
                "verified_artifact_count": 0, "execution_authorized": False}
    if len(set(available)) != len(available):
        return {"status": "DENY", "error": "DUPLICATE_MODEL_NAMES", "models": [], "count": 0,
                "verified_artifact_count": 0, "execution_authorized": False}
    return {"status": "OBSERVED_ONLY", "models": sorted(available), "count": len(available),
            "source": "ComfyUI CheckpointLoaderSimple name inventory (may be stale)",
            "verified_artifact_count": 0, "execution_authorized": False}


def workflow_inventory(raw: Any) -> dict:
    if not isinstance(raw, list) or len(raw) > MAX_WORKFLOWS:
        return {"status": "DENY", "error": "UNTRUSTED_WORKFLOW_CATALOG", "workflows": [], "count": 0,
                "execution_authorized": False}
    clean = []
    for item in raw:
        if not isinstance(item, dict) or not _SAFE_ID.fullmatch(str(item.get("id", ""))):
            return {"status": "DENY", "error": "UNTRUSTED_WORKFLOW_CATALOG", "workflows": [], "count": 0,
                    "execution_authorized": False}
        name = item.get("name")
        if not isinstance(name, str) or not (1 <= len(name) <= 160) or any(ord(c) < 32 for c in name):
            return {"status": "DENY", "error": "UNTRUSTED_WORKFLOW_CATALOG", "workflows": [], "count": 0,
                    "execution_authorized": False}
        clean.append({"id": item["id"], "name": name})
    if len({x["id"] for x in clean}) != len(clean):
        return {"status": "DENY", "error": "DUPLICATE_WORKFLOW_IDS", "workflows": [], "count": 0,
                "execution_authorized": False}
    return {"status": "OBSERVED_ONLY", "workflows": sorted(clean, key=lambda x:x["id"]), "count": len(clean),
            "verified_workflow_count": 0, "execution_authorized": False}



class ReadonlyWorkflowCatalog:
    """Names-only directory inventory; never parses workflow or metadata files.

    This is NOT a validated/approved workflow catalog. Bounded enumeration and
    no path-following prevent read-only startup from interpreting large or
    untrusted local JSON files merely for an MCP discovery tool.
    """

    MAX_DIR_ENTRIES = 2048

    def __init__(self, workflows_dir: Path):
        self.workflows_dir = Path(workflows_dir)

    def get_workflow_catalog(self) -> list[dict] | None:
        root = self.workflows_dir
        # Resolve the final path component exactly once. Pin the resulting
        # directory inode before listing names: path prechecks followed by
        # scandir(path) can follow a substituted symlink (TOCTOU).
        # This is Linux-specific and fails closed on platforms without flags.
        if not all(hasattr(os, flag) for flag in ("O_DIRECTORY", "O_NOFOLLOW")):
            return None
        flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0)
        try:
            directory_fd = os.open(root, flags)
        except FileNotFoundError:
            return []
        except OSError:
            return None
        try:
            names: list[dict] = []
            # scandir(fd) enumerates the opened directory, even if its name
            # is later renamed or replaced by a symlink. Never read file body.
            with os.scandir(directory_fd) as entries:
                for i, entry in enumerate(entries):
                    if i >= self.MAX_DIR_ENTRIES:
                        return None
                    name = entry.name
                    if not name.endswith(".json") or name.endswith(".meta.json"):
                        continue
                    if not entry.is_file(follow_symlinks=False):
                        return None
                    ident = name[:-5]
                    if not _SAFE_ID.fullmatch(ident):
                        return None
                    if len(names) >= MAX_WORKFLOWS:
                        return None
                    names.append({"id": ident, "name": ident.replace("_", " ").title()})
            return names
        except OSError:
            return None
        finally:
            os.close(directory_fd)

def register_superfluid_readonly_tools(mcp, comfyui_client, workflow_manager):
    """Register an explicit allowlist, not an effectful MCP tool manager."""
    @mcp.tool()
    def list_models() -> dict:
        return model_inventory(comfyui_client.available_models)

    @mcp.tool()
    def list_workflows() -> dict:
        return workflow_inventory(workflow_manager.get_workflow_catalog())

    @mcp.tool()
    def superfluid_worker_admission() -> dict:
        return {"status": "DENY", "reason": "NO_SIGNED_EXECUTION_PERMIT",
                "verified_artifact_count": 0, "gpu_attestation": False,
                "rights_attestation": False, "loader_attestation": False,
                "execution_authorized": False, "prompt_submission_allowed": False}
