import base64
from collections import Counter
from pathlib import Path
import tempfile
import threading
import time
import unittest
from unittest.mock import Mock, patch

import subscription as c
import update_protocols as u
import refresh
from vless import canonical
from test_vless import REALITY, xhttp


class Collection(unittest.TestCase):
    def test_plain_base64_and_invalid_source_reporting(self):
        source = {'id': 'test', 'url': 'https://example.org/list'}
        body = ('socks://8.8.8.8:1080\n' + REALITY + '\n' + xhttp() + '\n' + REALITY + '&type=grpc').encode()
        for payload in (body, base64.b64encode(body)):
            with patch.object(c, 'fetch_bytes', return_value=payload):
                nodes, report = u.fetch_source(source)
                self.assertEqual(len(nodes), 2)
                self.assertEqual(report['status'], 'ok')
                self.assertEqual(report['rejected'], {'other_protocol': 1, 'excluded_transport': 1})
        for payload in (b'<html>error</html>', b'garbage-base64', b'# not a subscription'):
            with patch.object(c, 'fetch_bytes', return_value=payload):
                self.assertEqual(u.fetch_source(source)[1]['status'], 'error')
        with patch.object(c, 'fetch_bytes', return_value=b''):
            self.assertEqual(u.fetch_source(source)[1]['status'], 'ok')

    def test_rotation_happens_before_cap_and_sources_are_deduplicated(self):
        nodes = [{'uri': canonical(REALITY + '&sid=' + f'{i:02x}'), 'transport': 'tcp_reality', 'sources': ['a']} for i in range(30)]
        other = [{'uri': canonical(xhttp()), 'transport': 'xhttp_tls', 'sources': ['b']}]
        def fetch(source):
            return (nodes if source['id'] == 'a' else other), {'id': source['id'], 'status': 'ok'}
        with patch.object(u, 'fetch_source', side_effect=fetch), patch.object(u, 'MAX_ITEMS', 4):
            first, _, _ = u.collect([{'id': 'a'}, {'id': 'b'}], epoch=1)
            second, _, _ = u.collect([{'id': 'a'}, {'id': 'b'}], epoch=2)
        self.assertEqual(len(first), 4)
        self.assertNotEqual(first, second)
        self.assertIn('xhttp_tls', [n['transport'] for n in first])

    def test_previous_nodes_are_candidates_only_and_fastest_rechecked_first(self):
        uris = [canonical(REALITY), canonical(xhttp())]
        chosen, total = u.candidates_with_history([], {uris[0]: {'speed_mbps': 20}, uris[1]: {'speed_mbps': 100}, 'socks://8.8.8.8:1080': {}})
        self.assertEqual(total, 2)
        self.assertEqual(chosen[0]['uri'], uris[1])
        self.assertNotIn('status', chosen[0])


class Verification(unittest.TestCase):
    def test_rejects_missing_second_https_or_dns_before_speed(self):
        process = Mock()
        process.poll.return_value = None
        sock = Mock()
        sock.__enter__ = Mock(return_value=sock)
        sock.__exit__ = Mock(return_value=None)
        sock.getsockname.return_value = ('127.0.0.1', 12345)
        for probes, dns, expected in [([100, None, None], True, 'https_failed'), ([100, 120], False, 'dns_failed')]:
            with patch.object(u.socket, 'socket', return_value=sock), patch.object(u.socket, 'create_connection', return_value=sock), patch.object(u.subprocess, 'run', return_value=Mock(returncode=0)), patch.object(u.subprocess, 'Popen', return_value=process), patch.object(c, 'probe', side_effect=probes), patch.object(c, 'check_dns', return_value=dns), patch.object(c, 'quality') as quality:
                result = u.verify({'uri': canonical(REALITY), 'transport': 'tcp_reality'}, time.monotonic() + 100, threading.BoundedSemaphore(1))
                self.assertEqual(result['status'], expected)
                quality.assert_not_called()
        self.assertEqual(process.terminate.call_count, 2)
        self.assertEqual(process.wait.call_count, 2)

    def test_stage_crash_publishes_empty_instead_of_old_fallback(self):
        with tempfile.TemporaryDirectory() as folder, patch.object(c, 'OUT', Path(folder)), patch.object(refresh.subprocess, 'Popen', return_value=Mock(wait=Mock(return_value=1))):
            c.atomic_write(Path(folder) / 'all.txt', REALITY + '\n')
            refresh.main()
            self.assertEqual((Path(folder) / 'all.txt').read_text(), '')
            self.assertEqual(c.load_json(Path(folder) / 'status.json')['error'], 'collector_failed')
