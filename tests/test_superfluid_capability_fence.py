"""M090: prove read-only runtime lacks inherited execution and JSON parser authority.

Synthetic temporary filesystem only; no network, ComfyUI or GPU.
"""
from __future__ import annotations

import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from comfyui_client import ComfyUIClient
from superfluid_safe_comfy import ReadonlyComfyUIClient, ReadonlyBoundaryDenied
from superfluid_readonly import ReadonlyWorkflowCatalog, workflow_inventory


class ReadonlyCapabilityFenceTests(unittest.TestCase):
    def test_readonly_client_is_not_effectful_superclass(self):
        self.assertFalse(issubclass(ReadonlyComfyUIClient, ComfyUIClient))
        self.assertEqual(ReadonlyComfyUIClient.__bases__, (object,))
        with patch.object(ReadonlyComfyUIClient, "_get_available_models", return_value=[]):
            client = ReadonlyComfyUIClient("http://127.0.0.1:8188")
        self.assertFalse(isinstance(client, ComfyUIClient))
        for attr in ("get_history", "get_queue", "refresh_models", "get_job", "get_prompt",
                     "_wait_for_prompt", "get_asset", "_get_asset_metadata", "load_workflow"):
            self.assertFalse(hasattr(client, attr), attr)
        self.assertEqual(set(client.__slots__), {"base_url", "available_models"})
        with self.assertRaises(AttributeError):
            client.secret_mutation_method = lambda: None

    def test_explicit_backward_compat_mutations_still_deny(self):
        with patch.object(ReadonlyComfyUIClient, "_get_available_models", return_value=[]):
            client = ReadonlyComfyUIClient("http://127.0.0.1:8188")
        for call in (lambda: client._queue_workflow({}),
                     lambda: client.run_custom_workflow({}),
                     lambda: client.cancel_prompt("id")):
            with self.assertRaises(ReadonlyBoundaryDenied):
                call()

    def test_catalog_reads_names_never_json_or_sidecar_contents(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            # Deliberately invalid JSON: loader must never parse it.
            (root / "video_prepare.json").write_bytes(b"not json " * 500000)
            (root / "video_prepare.meta.json").write_text('{"name":"SECRET-SIDECAR"}')
            with patch("builtins.open", side_effect=AssertionError("JSON_OPEN_FORBIDDEN")):
                actual = ReadonlyWorkflowCatalog(root).get_workflow_catalog()
            self.assertEqual(actual, [{"id": "video_prepare", "name": "Video Prepare"}])
            result = workflow_inventory(actual)
            self.assertEqual(result["status"], "OBSERVED_ONLY")
            self.assertFalse(result["execution_authorized"])
            self.assertEqual(result["verified_workflow_count"], 0)
            self.assertNotIn("SECRET-SIDECAR", str(result))

    def test_catalog_regular_json_symlink_denied(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            (root / "real").write_text("{}")
            (root / "evil.json").symlink_to(root / "real")
            self.assertIsNone(ReadonlyWorkflowCatalog(root).get_workflow_catalog())
            self.assertEqual(workflow_inventory(None)["status"], "DENY")

    def test_catalog_symlink_root_denied(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d)
            (p / "original").mkdir()
            (p / "link").symlink_to(p / "original", target_is_directory=True)
            self.assertIsNone(ReadonlyWorkflowCatalog(p / "link").get_workflow_catalog())

    def test_catalog_non_regular_json_denied(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d)
            (p / "nested.json").mkdir()
            self.assertIsNone(ReadonlyWorkflowCatalog(p).get_workflow_catalog())

    def test_catalog_invalid_id_denies_without_leaking_name(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d)
            (p / "unsafe name.json").write_text("{}")
            self.assertIsNone(ReadonlyWorkflowCatalog(p).get_workflow_catalog())
            self.assertNotIn("unsafe name", str(workflow_inventory(None)))

    def test_catalog_missing_dir_is_empty_observation(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "absent"
            self.assertEqual(ReadonlyWorkflowCatalog(p).get_workflow_catalog(), [])
            self.assertFalse(workflow_inventory([])["execution_authorized"])

    def test_catalog_file_instead_of_directory_denies(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "file"
            p.write_text("not a directory")
            self.assertIsNone(ReadonlyWorkflowCatalog(p).get_workflow_catalog())

    def test_catalog_permission_error_denies(self):
        with tempfile.TemporaryDirectory() as d:
            with patch("superfluid_readonly.os.scandir", side_effect=PermissionError):
                self.assertIsNone(ReadonlyWorkflowCatalog(Path(d)).get_workflow_catalog())

    def test_catalog_workflow_count_ceiling(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d)
            for i in range(501):
                (p / f"case_{i:03}.json").touch()
            self.assertIsNone(ReadonlyWorkflowCatalog(p).get_workflow_catalog())

    def test_catalog_entry_ceiling_even_with_unrelated_files(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d)
            for i in range(ReadonlyWorkflowCatalog.MAX_DIR_ENTRIES + 1):
                (p / f"irrelevant_{i:04}.txt").touch()
            self.assertIsNone(ReadonlyWorkflowCatalog(p).get_workflow_catalog())

    def test_catalog_only_returns_named_metadata_not_template(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d)
            (p / "run_video.json").write_text('{"nodes":{"class_type":"KSampler","token":"SECRET"}}')
            r = ReadonlyWorkflowCatalog(p).get_workflow_catalog()
            self.assertEqual(r, [{"id": "run_video", "name": "Run Video"}])
            self.assertNotIn("KSampler", str(r))
            self.assertNotIn("SECRET", str(r))


if __name__ == "__main__":
    unittest.main()
