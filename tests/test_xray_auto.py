"""Failover graph, bootstrap DNS, expiration and real Xray validation."""
import json
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

from test_incy import BASE
from xray_auto import build_auto


class AutoProfile(unittest.TestCase):
    def test_failover_and_dns_do_not_leak_general_traffic_to_direct(self):
        config, status = build_auto([BASE, 'socks://1.0.0.1:10800'])
        self.assertEqual(status['nodes'], {'vless': 1, 'socks': 1})
        out = {o['tag']: o for o in config['outbounds']}
        balances = {b['tag']: b for b in config['routing']['balancers']}
        self.assertEqual(balances['AUTO']['fallbackTag'], 'socks-fallback')
        self.assertEqual(balances['SOCKS']['fallbackTag'], 'block')
        self.assertEqual(out['socks-fallback']['settings']['inboundTag'], 'socks-fallback-in')
        self.assertEqual(config['routing']['rules'][0]['balancerTag'], 'SOCKS')
        self.assertEqual(config['routing']['rules'][-1]['balancerTag'], 'AUTO')
        self.assertEqual(out['SOCKS_001']['settings']['servers'][0]['port'], 10800)
        self.assertTrue(config['inbounds'][0]['sniffing']['routeOnly'])
        self.assertEqual(config['burstObservatory']['subjectSelector'], ['VLESS_', 'SOCKS_'])

    def test_empty_and_single_protocol_have_no_dangling_references(self):
        for uris in [[], [BASE], ['socks://1.0.0.1:10800']]:
            config, _ = build_auto(uris)
            tags = {o['tag'] for o in config['outbounds']}
            balancers = {b['tag'] for b in config['routing']['balancers']}
            self.assertEqual(config['outbounds'][0]['tag'], 'block')
            for b in config['routing']['balancers']:
                self.assertIn(b['fallbackTag'], tags)
            for r in config['routing']['rules']:
                if 'outboundTag' in r:
                    self.assertIn(r['outboundTag'], tags)
                if 'balancerTag' in r:
                    self.assertIn(r['balancerTag'], balancers)
            if not uris:
                self.assertNotIn('burstObservatory', config)
                self.assertEqual(config['routing']['rules'][-1]['outboundTag'], 'block')

    def test_domain_bootstrap_and_endpoint_deduplication(self):
        uri = BASE.replace('8.8.4.4', 'node.example.org')
        config, status = build_auto([uri, uri.replace('443?', '444?'), uri + '&sid=abcd'])
        self.assertEqual(status['nodes']['vless'], 2)
        self.assertIn('full:node.example.org', config['dns']['servers'][0]['domains'])
        self.assertEqual(config['outbounds'][1]['streamSettings']['realitySettings']['serverName'], 'example.org')

    @unittest.skipUnless(shutil.which('xray'), 'xray is not installed')
    def test_real_xray_accepts_all_failover_shapes_without_geodata(self):
        for uris in [[], [BASE], ['socks://1.0.0.1:10800'], [BASE, 'socks://1.0.0.1:10800']]:
            with tempfile.TemporaryDirectory() as folder:
                path = Path(folder) / 'auto.json'
                path.write_text(json.dumps(build_auto(uris)[0]))
                result = subprocess.run(['xray', 'run', '-test', '-config', str(path)],
                                        capture_output=True, text=True, timeout=10)
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
