from datetime import datetime, timezone, timedelta
import json
from pathlib import Path
import subprocess
import tempfile
import threading
import time
import unittest
from unittest.mock import Mock, patch
import subscription as c
from incy import profile, connection_digest
from vless import canonical
from test_vless import REALITY, xhttp

def record(uri=REALITY, speed=20, latency=100):
    uri = canonical(uri)
    return {'uri': uri, 'status': 'passed', 'speed_mbps': speed, 'speed_samples_mbps': [speed, speed + 1], 'latency_ms': latency, 'checked_at': c.timestamp(), 'quality_policy': c.QUALITY_POLICY, 'config_digest': connection_digest(profile(uri)), 'dns_ok': True, 'https_targets': list(c.TARGETS)}

class Quality(unittest.TestCase):
    def test_requires_two_complete_fast_downloads_and_retries_one_transient(self):
        for rates, expected in [([20, 25], 'passed'), ([2, 20, 25], 'passed'), ([None, 20, 25], 'passed'), ([2, 3], 'speed_rejected'), ([20, None, None], 'speed_unconfirmed')]:
            with self.subTest(rates=rates), patch.object(c, 'measure_speed', side_effect=rates):
                result = c.quality('proxy', time.monotonic() + 100, threading.BoundedSemaphore(1))
                self.assertEqual(result['status'], expected)
                if expected == 'passed': self.assertEqual(result['speed_mbps'], 20)

    def test_deadline_and_slot_release(self):
        slots = threading.BoundedSemaphore(1)
        self.assertEqual(c.quality('proxy', time.monotonic() - 1, slots)['status'], 'not_tested')
        with patch.object(c, 'measure_speed', side_effect=RuntimeError('test')):
            with self.assertRaises(RuntimeError): c.quality('proxy', time.monotonic() + 100, slots)
        self.assertTrue(slots.acquire(blocking=False))

    def test_speed_measurements_reject_partial_timeouts_wrong_size_and_nonfinite(self):
        for rc, body, expected in [(0, f'200 {c.SPEED_TEST_BYTES} 3 1', c.SPEED_TEST_BYTES * 4 / 1e6), (28, f'200 {c.SPEED_TEST_BYTES} 3 1', None), (0, '200 100 3 1', None), (0, '403 100 3 1', None), (0, f'200 {c.SPEED_TEST_BYTES} nan 0', None), (0, f'200 {c.SPEED_TEST_BYTES} 3 3', None)]:
            with patch.object(c, 'curl', return_value=Mock(returncode=rc, stdout=body.encode())):
                self.assertEqual(c.measure_speed('proxy'), expected)

    def test_curl_disables_dotfile_and_source_limits(self):
        with patch.object(c.subprocess, 'run', return_value=Mock(returncode=0, stdout=b'x')) as run:
            c.fetch_bytes('https://example.org/file')
            cmd = run.call_args.args[0]
            self.assertEqual(cmd[:2], ['curl', '--disable'])
            self.assertIn('--max-filesize', cmd)
            self.assertEqual(run.call_args.kwargs['timeout'], 16)
        with patch.object(c.subprocess, 'run', side_effect=subprocess.TimeoutExpired('curl', 15)):
            self.assertIsNone(c.measure_speed())

class Publication(unittest.TestCase):
    def test_speed_order_all_nodes_and_legacy_socks_cleanup(self):
        with tempfile.TemporaryDirectory() as folder, patch.object(c, 'OUT', Path(folder)):
            (Path(folder) / 'socks_state.json').write_text('{"old":true}')
            result = c.publish([record(REALITY, 20), record(xhttp(), 100)], {})
            self.assertEqual(result['published'], 2)
            configs = json.loads((Path(folder) / 'xray-auto.json').read_text())
            self.assertEqual(configs[1]['remarks'], 'XHTTP TLS | 8.8.8.8:443')
            self.assertEqual(configs[2]['remarks'], 'TCP REALITY | 8.8.8.8:443')
            self.assertEqual(len(json.loads((Path(folder) / 'incy.json').read_text())), 2)
            self.assertFalse((Path(folder) / 'socks_state.json').exists())
            self.assertEqual((Path(folder) / 'proxies.txt').read_text(), '')
            c.publish([dict(record(), status='dns_failed')], {})
            self.assertEqual(json.loads((Path(folder) / 'servers.json').read_text()), [])
            self.assertEqual(len(json.loads((Path(folder) / 'xray-auto.json').read_text())), 1)

    def test_rejects_stale_missing_or_tampered_measurements(self):
        good = record()
        self.assertTrue(c.valid_record(good['uri'], good))
        corruptions = [{'checked_at': (datetime.now(timezone.utc) - timedelta(hours=1)).isoformat()}, {'checked_at': '2099-01-01T00:00:00+00:00'}, {'checked_at': '2026-01-01'}, {'quality_policy': 'old'}, {'speed_mbps': float('nan')}, {'speed_mbps': 1000}, {'speed_samples_mbps': [20]}, {'latency_ms': 7000}, {'dns_ok': False}, {'https_targets': [c.TARGETS[0]]}, {'config_digest': 'different'}, {'status': 'not_tested'}]
        for changes in corruptions:
            with self.subTest(changes=changes): self.assertFalse(c.valid_record(good['uri'], dict(good, **changes)))
        self.assertFalse(c.valid_record('socks://8.8.8.8:1080', good))
        self.assertFalse(c.valid_record(REALITY + '&type=grpc', good))
