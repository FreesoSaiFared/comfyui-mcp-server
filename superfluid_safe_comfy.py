"""SUPERFLUID guarded ComfyUI discovery transport.

This confines the *read-only MCP process* to an exact literal loopback ComfyUI
address and prevents HTTP redirect/proxy-based egress during model discovery.
It cannot firewall ComfyUI's own port against other local/remote clients.
"""
from __future__ import annotations

from urllib.parse import urlsplit
import requests
from comfyui_client import ComfyUIClient


class ReadonlyBoundaryDenied(RuntimeError):
    pass


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
    base_url = validate_loopback_comfy_url(base_url)
    session = requests.Session()
    session.trust_env = False
    try:
        response = session.get(
            f"{base_url}/object_info/CheckpointLoaderSimple",
            timeout=5,
            allow_redirects=False,
            headers={"Accept": "application/json"},
        )
        if response.status_code != 200:
            return False
        payload = response.json()
        return isinstance(payload, dict) and isinstance(payload.get("CheckpointLoaderSimple"), dict)
    except (requests.RequestException, ValueError, TypeError, AttributeError):
        return False
    finally:
        session.close()


class ReadonlyComfyUIClient(ComfyUIClient):
    """Minimal inherited name parser but no queue/prompt or cancellation authority."""

    def __init__(self, base_url: str):
        base_url = validate_loopback_comfy_url(base_url)
        # Do not call superclass __init__: it uses requests.get with redirects
        # and trusts environment HTTP proxy settings.
        self.base_url = base_url
        self.available_models = self._get_available_models()

    def _get_available_models(self) -> list:
        session = requests.Session()
        session.trust_env = False
        try:
            response = session.get(
                f"{self.base_url}/object_info/CheckpointLoaderSimple",
                timeout=5,
                allow_redirects=False,
                headers={"Accept": "application/json"},
            )
            if response.status_code != 200:
                return []
            payload = response.json()
            values = payload.get("CheckpointLoaderSimple", {}).get("input", {}).get("required", {}).get("ckpt_name")
            if not isinstance(values, list) or not values or not isinstance(values[0], list):
                return []
            # Never use names as proof of model identity or safe execution.
            return values[0]
        except (requests.RequestException, ValueError, TypeError, AttributeError):
            return []
        finally:
            session.close()

    def _queue_workflow(self, workflow):
        raise ReadonlyBoundaryDenied("SUPERFLUID_READONLY_NO_PROMPT")

    def run_custom_workflow(self, *args, **kwargs):
        raise ReadonlyBoundaryDenied("SUPERFLUID_READONLY_NO_PROMPT")

    def cancel_prompt(self, *args, **kwargs):
        raise ReadonlyBoundaryDenied("SUPERFLUID_READONLY_NO_CANCEL")
