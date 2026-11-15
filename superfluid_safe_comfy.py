"""SUPERFLUID guarded ComfyUI discovery transport.

This confines the *read-only MCP process* to an exact literal loopback ComfyUI
address and prevents HTTP redirect/proxy-based egress during model discovery.
It cannot firewall ComfyUI's own port against other local/remote clients.
"""
from __future__ import annotations

import asyncio
import json
import zlib
from urllib.parse import urlsplit

import httpx


class ReadonlyBoundaryDenied(RuntimeError):
    pass


# A size cap and an absolute cooperative deadline are independent budgets.
# The async request phase is enclosed in wait_for, including HTTP header reads.
# The existing BODY_SECONDS constant is retained for backward compatibility
# with earlier tests and operators, but now covers the WHOLE transaction.
MAX_DISCOVERY_BYTES = 256 * 1024
DISCOVERY_CHUNK_BYTES = 8192
MAX_DISCOVERY_BODY_SECONDS = 4.0
DISCOVERY_IDLE_SECONDS = 0.75


async def _get_discovery_payload_async(base_url: str) -> dict | None:
    """GET only from literal loopback; bounded on wire and decompressed body."""
    timeout = httpx.Timeout(connect=2.0, read=DISCOVERY_IDLE_SECONDS,
                            write=DISCOVERY_IDLE_SECONDS, pool=DISCOVERY_IDLE_SECONDS)
    async with httpx.AsyncClient(trust_env=False, follow_redirects=False,
                                 timeout=timeout, http2=False) as client:
        async with client.stream(
            "GET", f"{base_url}/object_info/CheckpointLoaderSimple",
            headers={"Accept": "application/json", "Accept-Encoding": "identity"},
        ) as response:
            if response.status_code != 200:
                return None
            # Header length cannot be trusted; always check received bytes too.
            length = response.headers.get("Content-Length")
            if length is not None:
                if (len(length) > 12 or not length.isascii() or
                        not length.isdecimal() or int(length) > MAX_DISCOVERY_BYTES):
                    return None
            encoding = response.headers.get("Content-Encoding", "identity").strip().lower()
            if encoding not in {"identity", "gzip"}:
                return None
            decoder = zlib.decompressobj(16 + zlib.MAX_WBITS) if encoding == "gzip" else None
            body = bytearray()
            wire_bytes = 0
            # Raw iterator bypasses transparent compression and handles gzip
            # including optional headers before any decoded JSON is emitted.
            async for chunk in response.aiter_raw(chunk_size=DISCOVERY_CHUNK_BYTES):
                wire_bytes += len(chunk)
                if wire_bytes > MAX_DISCOVERY_BYTES:
                    return None
                if decoder is None:
                    part = chunk
                else:
                    try:
                        part = decoder.decompress(chunk, MAX_DISCOVERY_BYTES + 1 - len(body))
                    except zlib.error:
                        return None
                    if decoder.unused_data or decoder.unconsumed_tail:
                        return None
                if len(body) + len(part) > MAX_DISCOVERY_BYTES:
                    return None
                body.extend(part)
            if decoder is not None and not decoder.eof:
                return None
            try:
                result = json.loads(body)
            except (ValueError, UnicodeError, RecursionError, TypeError):
                return None
            return result if isinstance(result, dict) else None


def _read_discovery_payload(base_url: str) -> dict | None:
    """Synchronous startup-only bridge with a full async HTTP transaction cap.

    When called from a running event loop, fail closed instead of trying to
    nest asyncio.run or silently launch an uncontrolled worker thread. This
    class is initialized synchronously during server startup only.

    Cancellation is cooperative: the 4s limit covers async header and body
    I/O, but not arbitrary host scheduler stalls or malicious native code.
    """
    base_url = validate_loopback_comfy_url(base_url)
    try:
        asyncio.get_running_loop()
    except RuntimeError:
        pass
    else:
        return None
    try:
        return asyncio.run(asyncio.wait_for(
            _get_discovery_payload_async(base_url), timeout=MAX_DISCOVERY_BODY_SECONDS
        ))
    except (httpx.HTTPError, TimeoutError, OSError, RuntimeError):
        return None


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



def _snapshot_model_names(payload: object) -> list | None:
    """Extract the only trusted *shape* of checkpoint choices, not identity.

    A missing, malformed, or adversarial snapshot is UNAVAILABLE (None), not
    a valid empty inventory ([]). Values remain untrusted until the separate
    bounded model_inventory check; no filename here grants execution rights.
    """
    if type(payload) is not dict:
        return None
    node = payload.get("CheckpointLoaderSimple")
    if type(node) is not dict:
        return None
    inputs = node.get("input")
    if type(inputs) is not dict:
        return None
    required = inputs.get("required")
    if type(required) is not dict:
        return None
    field = required.get("ckpt_name")
    if type(field) is not list or not field or type(field[0]) is not list:
        return None
    choices = field[0]
    if not all(type(name) is str for name in choices):
        return None
    return choices


def safe_check_comfyui_available(base_url: str) -> bool:
    """Readonly preflight: no environment proxy, redirect, or non-loopback egress.

    The server uses this BEFORE client construction. This checks only reachability,
    not network isolation, trust in the reply, or execution authorization.
    """
    payload = _read_discovery_payload(base_url)
    return _snapshot_model_names(payload) is not None


class ReadonlyComfyUIClient:
    """Standalone discovery-only client; deliberately inherits no execution methods."""

    __slots__ = ("base_url", "available_models")

    def __init__(self, base_url: str):
        base_url = validate_loopback_comfy_url(base_url)
        # No superclass: effectful ComfyUIClient API is not inherited.
        self.base_url = base_url
        self.available_models = self._get_available_models()

    @classmethod
    def from_observed_payload(cls, base_url: str, payload: dict):
        """Construct from the single *startup* GET, without a second request.

        The supplied payload is untrusted discovery metadata, not an authority
        token or proof of a model's identity or rights. Only the server's
        guarded read-only startup path supplies this snapshot.
        """
        base_url = validate_loopback_comfy_url(base_url)
        names = _snapshot_model_names(payload)
        if names is None:
            raise ReadonlyBoundaryDenied("INVALID_READONLY_DISCOVERY_SNAPSHOT")
        instance = object.__new__(cls)
        instance.base_url = base_url
        instance.available_models = names
        return instance

    @staticmethod
    def _names_from_payload(payload: object) -> list | None:
        return _snapshot_model_names(payload)

    def _get_available_models(self) -> list | None:
        try:
            payload = _read_discovery_payload(self.base_url)
            # Keep invalid/unavailable data as None. model_inventory(None)
            # yields DENY, rather than laundering failures into OBSERVED_ONLY.
            return self._names_from_payload(payload)
        except (TypeError, AttributeError):
            return None

    def _queue_workflow(self, workflow):
        raise ReadonlyBoundaryDenied("SUPERFLUID_READONLY_NO_PROMPT")

    def run_custom_workflow(self, *args, **kwargs):
        raise ReadonlyBoundaryDenied("SUPERFLUID_READONLY_NO_PROMPT")

    def cancel_prompt(self, *args, **kwargs):
        raise ReadonlyBoundaryDenied("SUPERFLUID_READONLY_NO_CANCEL")
