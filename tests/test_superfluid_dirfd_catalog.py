"""M100: actual Linux directory-fd tests of read-only workflow name enumeration.

Synthetic temporary directories only; no actual worker, GPU, HTTP or model.
"""
from __future__ import annotations
import os
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest import TestCase
from unittest.mock import patch
import unittest
import superfluid_readonly as readonly


class CatalogDirfdTests(TestCase):
    def test_final_component_symlink_rejected(self):
        with TemporaryDirectory() as d:
            root=Path(d); target=root/'unrelated'; target.mkdir()
            (target/'secret.json').write_text('{}')
            (root/'configured').symlink_to(target, target_is_directory=True)
            self.assertIsNone(readonly.ReadonlyWorkflowCatalog(root/'configured').get_workflow_catalog())

    def test_rename_and_symlink_after_directory_open_does_not_follow(self):
        with TemporaryDirectory() as d:
            root=Path(d); configured=root/'configured'; configured.mkdir()
            (configured/'intended.json').write_text('{}')
            unrelated=root/'unrelated'; unrelated.mkdir()
            (unrelated/'private_secret.json').write_text('{}')
            original_scandir=os.scandir
            swapped=[]
            def replace_before_listing(directory_fd):
                self.assertIsInstance(directory_fd,int)
                if not swapped:
                    configured.rename(root/'renamed_original')
                    configured.symlink_to(unrelated,target_is_directory=True)
                    swapped.append(True)
                return original_scandir(directory_fd)
            with patch.object(readonly.os,'scandir',side_effect=replace_before_listing):
                names=readonly.ReadonlyWorkflowCatalog(configured).get_workflow_catalog()
            self.assertTrue(swapped)
            self.assertEqual(names,[{'id':'intended','name':'Intended'}])
            self.assertNotIn('private_secret',str(names))

    def test_open_uses_directory_and_no_follow_flags(self):
        with TemporaryDirectory() as d:
            p=Path(d)
            (p/'normal.json').write_text('{}')
            original_open=os.open
            captured=[]
            def observe_open(path, flags, *args, **kwargs):
                captured.append((path,flags))
                return original_open(path,flags,*args,**kwargs)
            with patch.object(readonly.os,'open',side_effect=observe_open):
                self.assertEqual(len(readonly.ReadonlyWorkflowCatalog(p).get_workflow_catalog()),1)
            self.assertGreaterEqual(len(captured),2)
            self.assertTrue(all(flags & os.O_DIRECTORY for _, flags in captured))
            self.assertTrue(all(flags & os.O_NOFOLLOW for _, flags in captured))
            self.assertTrue(all(flags & os.O_CLOEXEC for _, flags in captured))

    def test_closes_fd_on_scan_error(self):
        with TemporaryDirectory() as d:
            observed=[]
            def throw_error(fd):
                observed.append(fd)
                raise PermissionError('controlled refusal')
            with patch.object(readonly.os,'scandir',side_effect=throw_error):
                self.assertIsNone(readonly.ReadonlyWorkflowCatalog(Path(d)).get_workflow_catalog())
            self.assertEqual(len(observed),1)
            with self.assertRaises(OSError):
                os.fstat(observed[0])

    def test_missing_path_still_empty_unverified_inventory(self):
        with TemporaryDirectory() as d:
            result=readonly.ReadonlyWorkflowCatalog(Path(d)/'missing').get_workflow_catalog()
            self.assertEqual(result,[])
            self.assertFalse(readonly.workflow_inventory(result)['execution_authorized'])

    def test_non_directory_regular_file_denied(self):
        with TemporaryDirectory() as d:
            p=Path(d)/'not_a_directory';p.write_text('{}')
            self.assertIsNone(readonly.ReadonlyWorkflowCatalog(p).get_workflow_catalog())

    def test_root_fifo_rejected_without_open_blocking(self):
        if not hasattr(os,'mkfifo'):
            self.skipTest('non POSIX')
        with TemporaryDirectory() as d:
            p=Path(d)/'fifo';os.mkfifo(p)
            self.assertIsNone(readonly.ReadonlyWorkflowCatalog(p).get_workflow_catalog())

    def test_symlinked_workflow_entry_still_denied(self):
        with TemporaryDirectory() as d:
            p=Path(d);(p/'normal.json').write_text('{}')
            (p/'linked.json').symlink_to(p/'normal.json')
            self.assertIsNone(readonly.ReadonlyWorkflowCatalog(p).get_workflow_catalog())

    def test_no_untrusted_workflow_json_read(self):
        with TemporaryDirectory() as d:
            p=Path(d);(p/'corrupt.json').write_bytes(b'\\x00'*10000)
            with patch('builtins.open',side_effect=AssertionError('FILE_BODY_READ_FORBIDDEN')):
                v=readonly.ReadonlyWorkflowCatalog(p).get_workflow_catalog()
            self.assertEqual(v,[{'id':'corrupt','name':'Corrupt'}])
            self.assertFalse(readonly.workflow_inventory(v)['execution_authorized'])

    def test_catalog_limit_retained(self):
        with TemporaryDirectory() as d:
            p=Path(d)
            for n in range(readonly.MAX_WORKFLOWS+1):
                (p/f'test_{n:04d}.json').touch()
            self.assertIsNone(readonly.ReadonlyWorkflowCatalog(p).get_workflow_catalog())

if __name__=='__main__':
    unittest.main()
