"""Measured speed qualification with retries for transient slowness."""
import subprocess
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

import subscription as common
import update as socks
import update_protocols as vless
from test_subscription import BASE


class Quality(unittest.TestCase):
    def test_two_slow_samples_reject_but_one_recovers(self):
        for samples, expected in [([common.MIN_SPEED_MBPS * 0.3, common.MIN_SPEED_MBPS * 0.4], 'speed_rejected'),
                                  ([common.MIN_SPEED_MBPS * 0.3, common.MIN_SPEED_MBPS * 2], 'passed'),
                                  ([0.03, None], 'quality_inconclusive'), ([None], 'quality_inconclusive'),
                                  ([common.MIN_SPEED_MBPS], 'passed')]:
            with self.subTest(samples=samples), patch.object(common, 'measure_speed', side_effect=samples):
                self.assertEqual(common.filter_quality('proxy', common.TARGETS, 1000, True)[0], expected)

    def test_unhealthy_baseline_never_rejects_speed(self):
        with patch.object(common, 'measure_speed') as speed:
            self.assertEqual(common.filter_quality('proxy', common.TARGETS, 1000, False)[0], 'quality_inconclusive')
            speed.assert_not_called()
        for rate, expected in [(None, False), (common.MIN_SPEED_MBPS, False), (common.MIN_SPEED_MBPS * 4, True)]:
            with patch.object(common, 'measure_speed', return_value=rate):
                self.assertEqual(common.speed_baseline(), expected)

    def test_repeated_latency_and_transient_recovery(self):
        for retry, expected in [(('passed', 6500), 'latency_rejected'),
                                (('passed', 1000), 'passed'),
                                (('unreachable', None), 'quality_inconclusive')]:
            with patch.object(common, 'connectivity', return_value=retry), patch.object(common, 'measure_speed', return_value=common.MIN_SPEED_MBPS):
                self.assertEqual(common.filter_quality('proxy', common.TARGETS, 6500, True)[0], expected)

    def test_speed_blocks_and_partial_timeout(self):
        for code, stdout, expected in [(22, b'403 100 3 1', None),
                                       (0, f'200 {common.SPEED_TEST_BYTES} 3 1'.encode(), common.SPEED_TEST_BYTES * 8 / 2 / 1000000),
                                       (28, b'200 32768 14 2', 32768 * 8 / 12 / 1000000),
                                       (28, b'000 0 14 0', None),
                                       (0, b'200 120 3 1', None)]:
            with patch.object(common, 'curl', return_value=Mock(returncode=code, stdout=stdout)):
                self.assertEqual(common.measure_speed('proxy'), expected)
        with patch.object(common, 'curl', side_effect=subprocess.TimeoutExpired('curl', 15)):
            self.assertIsNone(common.measure_speed('proxy'))

    def test_deadline_does_not_accept_unconfirmed_slow_sample(self):
        with patch.object(common, 'measure_speed', return_value=0.02), patch.object(common.time, 'monotonic', side_effect=[0, 10]):
            self.assertEqual(common.filter_quality('proxy', common.TARGETS, 1000, True, 20)[0], 'quality_inconclusive')

    def test_no_budget_cannot_bypass_speed_check(self):
        with patch.object(common.time, 'monotonic', return_value=10), patch.object(common, 'measure_speed') as speed:
            self.assertEqual(common.filter_quality('proxy', common.TARGETS, 1000, True, 20)[0], 'quality_inconclusive')
            speed.assert_not_called()

    def test_socks_uses_same_tunnel_quality_filter(self):
        with patch.object(socks, 'connectivity', return_value=('passed', 1000)), patch.object(socks, 'filter_quality', return_value=('speed_rejected', 1000)) as quality:
            self.assertEqual(socks.check('socks://1.0.0.1:10800', common.TARGETS, baseline_ok=True)[1], 'speed_rejected')
            self.assertEqual(quality.call_args.args[0], 'socks5h://1.0.0.1:10800')

    def test_old_policy_and_rejected_nodes_cannot_survive_in_json(self):
        with tempfile.TemporaryDirectory() as folder, patch.object(common, 'OUT', Path(folder)), patch.object(common, 'country_labels', return_value={}):
            uri = vless.canonical_reality(BASE)
            common.write_json(Path(folder) / 'vless_state.json', {'nodes': {uri: {'last_verified_at': common.timestamp()}}})
            self.assertEqual(common.previous('vless', vless.canonical_reality)[1], {})
            old = {uri: {'last_verified_at': common.timestamp(), 'quality_policy': common.QUALITY_POLICY}}
            common.publish('vless', 'vless.txt', [(uri, 'speed_rejected', None)], old, 1, {}, {})
            common.merge()
            self.assertEqual(common.lines(Path(folder) / 'all.txt'), [])
            import json
            for name in ('incy.json', 'xray-auto.json'):
                configs = json.loads((Path(folder) / name).read_text())
                self.assertFalse(any(o['protocol'] == 'vless' for c in configs for o in c['outbounds']))
