"""Synthetic-only tests for M086 /proc observer; never contacts a host or GPU."""
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from superfluid_host_observer import collect_snapshot, parse_tcp_listeners, save_no_overwrite, _start_ticks

HEADER = '  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n'

def tcp_line(ip='0100007F',port=8188,inode=101,state='0A'):
    return f'   0: {ip}:{port:04X} 00000000:0000 {state} 00000000:00000000 00:00000000 00000000  1000 0 {inode} 1 0000000000000000 100 0 0 10 0\n'

def proc_stat(pid, ticks):
    # 1:pid 2:comm 3:state; pad to 22:starttime
    return f'{pid} (python) S ' + ' '.join(['0']*18 + [str(ticks)] + ['0']*4) + '\n'


def fake_proc(root, pid, port, ip='0100007F', inode=101, netns='net:[4026531993]'):
    base = root / str(pid)
    (base / 'fd').mkdir(parents=True)
    (base / 'net').mkdir()
    (base / 'ns').mkdir()
    (base / 'stat').write_text(proc_stat(pid,10))
    (base / 'ns' / 'net').symlink_to(netns)
    (base / 'fd' / '3').symlink_to(f'socket:[{inode}]')
    (base / 'net' / 'tcp').write_text(HEADER + tcp_line(ip,port,inode))
    (base / 'net' / 'tcp6').write_text(HEADER)
    return base


class SyntheticSnapshotTests(unittest.TestCase):
    def setup_proc(self, root, *, ip='0100007F'):
        p = Path(root)
        fake_proc(p,101,8188,ip=ip,inode=101)
        fake_proc(p,102,9000,inode=102)
        return p

    def snapshot(self, root, **changes):
        params={'host_label':'synthetic','comfyui_pid':101,'mcp_pid':102,
                'comfyui_port':8188,'mcp_port':9000,'proc_root':root}
        params.update(changes)
        return collect_snapshot(**params)

    def assert_denied(self,r):
        self.assertEqual(r['status'],'DENY')
        self.assertFalse(r['execution_authorized'])
        self.assertFalse(r['prompt_submission_allowed'])
        self.assertFalse(r['host_isolation_proven'])
        self.assertFalse(r['authoritative_attestation'])
        self.assertFalse(r['network_calls_performed'])
        self.assertFalse(r['gpu_inference_performed'])

    def test_loopback_clean_still_deny(self):
        with tempfile.TemporaryDirectory() as d:
            r=self.snapshot(self.setup_proc(d))
            self.assert_denied(r)
            self.assertEqual(r['assessment'],'UNVERIFIED')
            self.assertEqual(r['blockers'],[])
            self.assertEqual(r['observed_processes']['comfyui']['tcp_listeners'],
                             [{'bind_ip':'127.0.0.1','port':8188}])

    def test_public_wildcard_detected(self):
        with tempfile.TemporaryDirectory() as d:
            r=self.snapshot(self.setup_proc(d,ip='00000000'))
            self.assert_denied(r)
            self.assertIn('COMFYUI_NON_LITERAL_LOOPBACK_LISTENER',r['blockers'])

    def test_lan_bind_detected(self):
        with tempfile.TemporaryDirectory() as d:
            r=self.snapshot(self.setup_proc(d,ip='0101A8C0'))  # 192.168.1.1
            self.assertIn('COMFYUI_NON_LITERAL_LOOPBACK_LISTENER',r['blockers'])

    def test_missing_fd_fails_closed(self):
        with tempfile.TemporaryDirectory() as d:
            root=self.setup_proc(d)
            (root/'101'/'fd'/'3').unlink()
            r=self.snapshot(root)
            self.assertIn('COMFYUI_EXPECTED_LISTENER_NOT_PROVEN',r['blockers'])

    def test_invisible_pid_fails_closed(self):
        with tempfile.TemporaryDirectory() as d:
            root=self.setup_proc(d)
            r=self.snapshot(root,comfyui_pid=8080)
            self.assertIn('COMFYUI_PROC_OBSERVATION_INCOMPLETE',r['blockers'])

    def test_same_pid_rejected_as_ambiguous(self):
        with tempfile.TemporaryDirectory() as d:
            r=self.snapshot(self.setup_proc(d),mcp_pid=101)
            self.assertIn('SAME_PID_FOR_COMFYUI_AND_MCP',r['blockers'])

    def test_additional_listener_reported(self):
        with tempfile.TemporaryDirectory() as d:
            root=self.setup_proc(d)
            (root/'101'/'fd'/'4').symlink_to('socket:[111]')
            with (root/'101'/'net'/'tcp').open('a') as f:
                f.write(tcp_line('0100007F',8222,111))
            r=self.snapshot(root)
            self.assertIn('COMFYUI_ADDITIONAL_TCP_LISTENER_OBSERVED',r['blockers'])

    def test_tcp_file_over_limit_fails_closed(self):
        with tempfile.TemporaryDirectory() as d:
            root=self.setup_proc(d)
            with (root/'101'/'net'/'tcp').open('a') as f:f.write(' '*(1024*1024+1))
            r=self.snapshot(root)
            self.assertIn('COMFYUI_PROC_OBSERVATION_INCOMPLETE',r['blockers'])

    def test_netns_changed_during_snapshot_fails_closed(self):
        with tempfile.TemporaryDirectory() as d:
            root=self.setup_proc(d)
            original=os.readlink
            counter=[]
            def changing(p):
                if str(p).endswith('/101/ns/net'):
                    counter.append(1)
                    if len(counter)==2:return 'net:[404404404]'
                return original(p)
            with patch('superfluid_host_observer.os.readlink',side_effect=changing):
                r=self.snapshot(root)
            self.assertIn('COMFYUI_PROC_OBSERVATION_INCOMPLETE',r['blockers'])

    def test_wrong_expected_port(self):
        with tempfile.TemporaryDirectory() as d:
            r=self.snapshot(self.setup_proc(d),comfyui_port=8189)
            self.assertIn('COMFYUI_EXPECTED_LISTENER_NOT_PROVEN',r['blockers'])

    def test_bool_port_rejected(self):
        with tempfile.TemporaryDirectory() as d:
            r=self.snapshot(self.setup_proc(d),mcp_port=True)
            self.assertIn('MCP_INVALID_EXPECTED_PORT',r['blockers'])

    def test_invalid_pid(self):
        with tempfile.TemporaryDirectory() as d:
            r=self.snapshot(self.setup_proc(d),comfyui_pid=-1)
            self.assertIn('COMFYUI_PROC_OBSERVATION_INCOMPLETE',r['blockers'])

    def test_invalid_label(self):
        with tempfile.TemporaryDirectory() as d:
            r=self.snapshot(self.setup_proc(d),host_label='../bad')
            self.assertIn('INVALID_HOST_LABEL',r['blockers'])

    def test_ipv6_loopback_parsing(self):
        sample=HEADER + tcp_line('00000000000000000000000001000000',port=9000)
        x=parse_tcp_listeners(sample,ipv6=True)
        self.assertEqual(x[0]['bind_ip'],'::1')

    def test_ipv6_wildcard_parsing(self):
        sample=HEADER + tcp_line('0'*32,port=9000)
        self.assertEqual(parse_tcp_listeners(sample,ipv6=True)[0]['bind_ip'],'::')

    def test_non_listen_tcp_ignored(self):
        sample=HEADER + tcp_line(state='01')
        self.assertEqual(parse_tcp_listeners(sample,ipv6=False),[])

    def test_malformed_tcp_header_rejected(self):
        with self.assertRaises(ValueError):parse_tcp_listeners('bad\n',ipv6=False)

    def test_malformed_tcp_row_rejected(self):
        with self.assertRaises(ValueError):parse_tcp_listeners(HEADER+'bad\n',ipv6=False)

    def test_port_zero_rejected(self):
        with self.assertRaises(ValueError):parse_tcp_listeners(HEADER+tcp_line(port=0),ipv6=False)

    def test_executable_name_parentheses_parsed(self):
        with tempfile.TemporaryDirectory() as d:
            p=Path(d)/'stat'
            p.write_text('101 (task) name) S '+' '.join(['0']*18+['97']+['0']*4))
            self.assertEqual(_start_ticks(p),'97')

    def test_pid_reuse_rejected(self):
        with tempfile.TemporaryDirectory() as d:
            root=self.setup_proc(d)
            from superfluid_host_observer import _start_ticks as original
            calls=[]
            def changed(p):
                if str(p).endswith('/101/stat'):
                    calls.append(1)
                    if len(calls)==2:return '999'
                return original(p)
            with patch('superfluid_host_observer._start_ticks',side_effect=changed):
                r=self.snapshot(root)
            self.assertIn('COMFYUI_PROC_OBSERVATION_INCOMPLETE',r['blockers'])

    def test_netns_invalid_rejected(self):
        with tempfile.TemporaryDirectory() as d:
            root=self.setup_proc(d)
            (root/'101'/'ns/net').unlink()
            (root/'101'/'ns/net').symlink_to('garbled')
            r=self.snapshot(root)
            self.assertIn('COMFYUI_PROC_OBSERVATION_INCOMPLETE',r['blockers'])

    def test_no_socket_or_network_calls(self):
        with tempfile.TemporaryDirectory() as d:
            root=self.setup_proc(d)
            with patch('socket.socket',side_effect=AssertionError('NETWORK_CALL')):
                r=self.snapshot(root)
            self.assert_denied(r)

    def test_two_network_namespaces_not_proof(self):
        with tempfile.TemporaryDirectory() as d:
            root=self.setup_proc(d)
            (root/'102'/'ns/net').unlink()
            (root/'102'/'ns/net').symlink_to('net:[4026532000]')
            r=self.snapshot(root)
            self.assert_denied(r)
            self.assertIn('PROCESS_NAMESPACE_RELATION_UNVERIFIED',r['unverified'])

    def test_save_receipt_private_and_atomic(self):
        with tempfile.TemporaryDirectory() as d:
            path=Path(d)/'report.json'
            save_no_overwrite(path,{'status':'DENY'})
            self.assertEqual(path.stat().st_mode & 0o777,0o600)
            with self.assertRaises(FileExistsError):
                save_no_overwrite(path,{'status':'ALLOW'})
            self.assertEqual(json.loads(path.read_text())['status'],'DENY')

    def test_save_refuses_symlink(self):
        with tempfile.TemporaryDirectory() as d:
            real=Path(d)/'real'
            real.write_text('unchanged')
            link=Path(d)/'link.json'
            link.symlink_to(real)
            with self.assertRaises(FileExistsError):save_no_overwrite(link,{'status':'DENY'})
            self.assertEqual(real.read_text(),'unchanged')


if __name__=='__main__':unittest.main()
