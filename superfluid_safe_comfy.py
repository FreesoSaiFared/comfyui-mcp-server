"""SUPERFLUID guarded ComfyUI discovery transport.

This confines the *read-only MCP process* to an exact literal loopback ComfyUI
address and prevents HTTP redirect/proxy-based egress during model discovery.
It cannot firewall ComfyUI's own port against other local/remote clients.
"""
from __future__ import annotations

import json
from urllib.parse import urlsplit
import requests


class ReadonlyBoundaryDenied(RuntimeError):
    pass


# The API is untrusted input even over literal loopback. Responses are decoded
# by iter_content, so this is a cap on *decompressed* bytes too.
MAX_DISCOVERY_BYTES = 256 * 1024
DISCOVERY_CHUNK_BYTES = 8192


def _read_discovery_payload(base_url: str) -> dict | None:
    """One bounded GET; never redirects, uses proxies or executes a workflow."""
    base_url = validate_loopback_comfy_url(base_url)
    with requests.Session() as session:
        session.trust_env = False
        with session.get(
            f"{base_url}/object_info/CheckpointLoaderSimple",
            timeout=(3, 5),
            allow_redirects=False,
            stream=True,
            headers={"Accept": "application/json", "Accept-Encoding": "identity"},
        ) as response:
            if response.status_code != 200:
                return None
            # Cheap early rejection only: Content-Length can be absent/false.
            length = response.headers.get("Content-Length")
            if length is not None:
                if len(length) > 12 or not length.isascii() or not length.isdecimal() or int(length) > MAX_DISCOVERY_BYTES:
                    return None
            body = bytearray()
            for part in response.iter_content(chunk_size=DISCOVERY_CHUNK_BYTES):
                if len(body) + len(part) > MAX_DISCOVERY_BYTES:
                    return None
                body.extend(part)
            try:
                payload = json.loads(body)
            except (ValueError, UnicodeError, RecursionError, TypeError):
                return None
            if not isinstance(payload, dict):
                return None
            return payload


def validate_loopback_comfy_url(value: str) -> str:
    if not isinstance(value, str) or not value or any(ord(c) < 33 or ord(c) == 127 for c in value):
        raise ReadonlyBoundaryDenied("UNSAFE_COMFYUI_URL")
    try:
        parts = urlsplit(value)
        port = parts.port
    except (ValueError, TypeError):
        raise ReadonlyBoundaryDenied("UNSAFE_COMFYUI_URL") from None
    if (
        parts.scheme not in {"http", "https"}
        or parts.hostname not in {"127.0.0.1", "::1"}
        or not isinstance(port, int)
        or not (1 <= port <= 65535)
        or parts.username is not None
        or parts.password is not None
        or parts.query
        or parts.fragment
        or parts.path not in {"", "/"}
        or parts.netloc.startswith("@")
    ):
        raise ReadonlyBoundaryDenied("UNSAFE_COMFYUI_URL")
    # Reconstruct normalized authority; never preserve arbitrary path or query.
    host = f"[{parts.hostname}]" if ":" in parts.hostname else parts.hostname
    return f"{parts.scheme}://{host}:{port}"


def safe_check_comfyui_available(base_url: str) -> bool:
    """Readonly preflight: no environment proxy, redirect, or non-loopback egress.

    The server uses this BEFORE client construction. This checks only reachability,
    not network isolation, trust in the reply, or execution authorization.
    """
    try:
        payload = _read_discovery_payload(base_url)
        return isinstance(payload, dict) and isinstance(payload.get("CheckpointLoaderSimple"), dict)
    except requests.RequestException:
        return False


class ReadonlyComfyUIClient:
    """Standalone discovery-only client; deliberately inherits no execution methods."""

    __slots__ = ("base_url", "available_models")

    def __init__(self, base_url: str):
        base_url = validate_loopback_comfy_url(base_url)
        # No superclass: effectful ComfyUIClient API is not inherited.
        self.base_url = base_url
        self.available_models = self._get_available_models()

    def _get_available_models(self) -> list:
        try:
            payload = _read_discovery_payload(self.base_url)
            if not isinstance(payload, dict):
                return []
            values = payload.get("CheckpointLoaderSimple", {}).get("input", {}).get("required", {}).get("ckpt_name")
            if not isinstance(values, list) or not values or not isinstance(values[0], list):
                return []
            # The MCP inventory function still validates names and count.
            # No model filename can authorize inference or verify its bytes.
            return values[0]
        except (requests.RequestException, TypeError, AttributeError):
            return []

    def _queue_workflow(self, workflow):
        raise ReadonlyBoundaryDenied("SUPERFLUID_READONLY_NO_PROMPT")

    def run_custom_workflow(self, *args, **kwargs):
        raise ReadonlyBoundaryDenied("SUPERFLUID_READONLY_NO_PROMPT")

    def cancel_prompt(self, *args, **kwargs):
        raise ReadonlyBoundaryDenied("SUPERFLUID_READONLY_NO_CANCEL")
