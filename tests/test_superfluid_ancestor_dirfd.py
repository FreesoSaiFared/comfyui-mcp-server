"""M101: Linux ancestor-symlink and path-component race tests for read-only catalog.

All filesystem effects are isolated to disposable temporary directories; no
network, model reads, GPU, model download, or production process is used.
"""
from __future__ import annotations

import os
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest import TestCase
from unittest.mock import patch

from superfluid_readonly import ReadonlyWorkflowCatalog


class AncestorDirfdTests(TestCase):
    def test_existing_ancestor_symlink_is_denied(self):
        with TemporaryDirectory() as d:
            base = Path(d)
            redirected = base / "redirected"
            (redirected / "catalog").mkdir(parents=True)
            (redirected / "catalog" / "secret.json").write_text("{}")
            (base / "alias").symlink_to(redirected, target_is_directory=True)
            self.assertIsNone(
                ReadonlyWorkflowCatalog(base / "alias" / "catalog").get_workflow_catalog()
            )

    def test_ancestor_swap_during_walk_uses_pinned_inode(self):
        with TemporaryDirectory() as d:
            base = Path(d)
            trusted = base / "trusted"
            (trusted / "catalog").mkdir(parents=True)
            (trusted / "catalog" / "intended.json").write_text("{}")
            attacker = base / "attacker"
            (attacker / "catalog").mkdir(parents=True)
            (attacker / "catalog" / "private_secret.json").write_text("{}")
            real_open = os.open
            swapped = []

            def swap_before_child_open(path, flags, *args, **kwargs):
                if path == "catalog" and kwargs.get("dir_fd") is not None and not swapped:
                    trusted.rename(base / "renamed_trusted")
                    trusted.symlink_to(attacker, target_is_directory=True)
                    swapped.append(True)
                return real_open(path, flags, *args, **kwargs)

            with patch("superfluid_readonly.os.open", side_effect=swap_before_child_open):
                result = ReadonlyWorkflowCatalog(trusted / "catalog").get_workflow_catalog()
            self.assertTrue(swapped)
            self.assertEqual(result, [{"id": "intended", "name": "Intended"}])
            self.assertNotIn("private_secret", str(result))

    def test_each_component_uses_nofollow_and_parent_dirfd(self):
        with TemporaryDirectory() as d:
            base = Path(d)
            (base / "workflows").mkdir()
            (base / "workflows" / "safe.json").touch()
            original_open = os.open
            calls = []

            def observe(path, flags, *args, **kwargs):
                calls.append((str(path), flags, kwargs))
                return original_open(path, flags, *args, **kwargs)

            with patch("superfluid_readonly.os.open", side_effect=observe):
                result = ReadonlyWorkflowCatalog(base / "workflows").get_workflow_catalog()
            self.assertEqual(result, [{"id": "safe", "name": "Safe"}])
            self.assertGreaterEqual(len(calls), 3)
            self.assertEqual(calls[0][0], os.path.sep)
            self.assertTrue(all(flags & os.O_NOFOLLOW for _, flags, _ in calls))
            self.assertTrue(all(flags & os.O_DIRECTORY for _, flags, _ in calls))
            self.assertTrue(all(flags & os.O_CLOEXEC for _, flags, _ in calls))
            self.assertTrue(all("dir_fd" in kwargs for _, _, kwargs in calls[1:]))

    def test_parent_traversal_dotdot_is_denied(self):
        with TemporaryDirectory() as d:
            p = Path(d) / "intermediate" / ".." / "workflows"
            self.assertIn("..", p.parts)
            self.assertIsNone(ReadonlyWorkflowCatalog(p).get_workflow_catalog())

    def test_excessive_component_depth_fails_closed(self):
        with TemporaryDirectory() as d:
            p = Path(d).joinpath(*[f"part_{i}" for i in range(65)])
            self.assertIsNone(ReadonlyWorkflowCatalog(p).get_workflow_catalog())

    def test_missing_nested_directory_denies_unavailable_catalog(self):
        with TemporaryDirectory() as d:
            p = Path(d) / "missing" / "catalog"
            self.assertIsNone(ReadonlyWorkflowCatalog(p).get_workflow_catalog())

    def test_missing_final_directory_denies_unavailable_catalog(self):
        with TemporaryDirectory() as d:
            p = Path(d) / "missing"
            self.assertIsNone(ReadonlyWorkflowCatalog(p).get_workflow_catalog())

    def test_existing_empty_directory_is_observed_empty(self):
        with TemporaryDirectory() as d:
            p = Path(d) / "catalog"
            p.mkdir()
            self.assertEqual(ReadonlyWorkflowCatalog(p).get_workflow_catalog(), [])

    def test_directory_removed_during_component_walk_denies(self):
        with TemporaryDirectory() as d:
            base = Path(d)
            parent = base / "parent"
            catalog = parent / "catalog"
            catalog.mkdir(parents=True)
            real_open = os.open
            removed = []

            def remove_before_child_open(path, flags, *args, **kwargs):
                if path == "catalog" and kwargs.get("dir_fd") is not None and not removed:
                    catalog.rmdir()
                    removed.append(True)
                return real_open(path, flags, *args, **kwargs)

            with patch("superfluid_readonly.os.open", side_effect=remove_before_child_open):
                result = ReadonlyWorkflowCatalog(catalog).get_workflow_catalog()
            self.assertTrue(removed)
            self.assertIsNone(result)

    def test_intermediate_permission_error_closes_all_open_fds(self):
        with TemporaryDirectory() as d:
            base = Path(d)
            (base / "blocked" / "catalog").mkdir(parents=True)
            real_open = os.open
            opened = []

            def block(path, flags, *args, **kwargs):
                if path == "blocked":
                    raise PermissionError("injected permission failure")
                fd = real_open(path, flags, *args, **kwargs)
                opened.append(fd)
                return fd

            with patch("superfluid_readonly.os.open", side_effect=block):
                self.assertIsNone(
                    ReadonlyWorkflowCatalog(base / "blocked" / "catalog").get_workflow_catalog()
                )
            self.assertGreater(len(opened), 0)
            for fd in set(opened):
                with self.assertRaises(OSError):
                    os.fstat(fd)

    def test_unsupported_dirfd_platform_is_denied(self):
        with TemporaryDirectory() as d:
            with patch("superfluid_readonly.os.supports_dir_fd", set()):
                self.assertIsNone(ReadonlyWorkflowCatalog(Path(d)).get_workflow_catalog())

    def test_relative_path_is_walked_from_pinned_cwd(self):
        with TemporaryDirectory() as d:
            base = Path(d)
            (base / "sub" / "workflows").mkdir(parents=True)
            (base / "sub" / "workflows" / "relative.json").touch()
            original_cwd = os.getcwd()
            try:
                os.chdir(base)
                got = ReadonlyWorkflowCatalog(Path("sub/workflows")).get_workflow_catalog()
                self.assertEqual(got, [{"id": "relative", "name": "Relative"}])
            finally:
                os.chdir(original_cwd)

    def test_workflow_catalog_still_never_reads_body(self):
        with TemporaryDirectory() as d:
            base = Path(d)
            (base / "nested" / "workflows").mkdir(parents=True)
            (base / "nested" / "workflows" / "corrupt.json").write_bytes(b"\\x00" * 1024)
            with patch("builtins.open", side_effect=AssertionError("unexpected file body read")):
                self.assertEqual(
                    ReadonlyWorkflowCatalog(base / "nested" / "workflows").get_workflow_catalog(),
                    [{"id": "corrupt", "name": "Corrupt"}],
                )
