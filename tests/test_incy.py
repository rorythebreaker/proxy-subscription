"""DNS/routing semantics and independent Xray profile export."""
import json
import shutil
import subprocess
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import patch

import incy
import subscription as common
from update_protocols import canonical_reality

BASE = ('vless://00000000-0000-4000-8000-000000000000@8.8.4.4:443'
        '?security=reality&sni=example.org&pbk=' + 'A' * 43)


class IncyExport(unittest.TestCase):
    def test_all_profiles_have_explicit_dns_no_fake_dns_and_loopback_inbounds(self):
        profiles, status = incy.build_subscription([BASE, 'socks://1.0.0.1:1080#AU%201.0.0.1'])
        self.assertEqual(status['published'], 2)
        self.assertEqual(status['skipped'], {})
        for profile in profiles:
            self.assertEqual(profile['dns']['servers'], ['8.8.8.8', '1.1.1.1'])
            self.assertEqual(profile['dns']['queryStrategy'], 'UseIPv4')
            self.assertNotIn('fakedns', json.dumps(profile).lower())
            self.assertEqual([(i['listen'], i['port']) for i in profile['inbounds']],
                             [('127.0.0.1', 10808), ('127.0.0.1', 10809)])
            self.assertTrue(all(i['sniffing']['enabled'] for i in profile['inbounds']))

    def test_preserve_reality_credentials_flow_sni_fingerprint_shortid_spider(self):
        profile = incy.profile(BASE + '&flow=xtls-rprx-vision&sid=12ab&fp=firefox&spx=%2Fhello#DE%20server')
        outbound = profile['outbounds'][0]
        self.assertEqual(profile['remarks'], 'VLESS DE server')
        self.assertEqual(outbound['tag'], profile['remarks'])
        self.assertEqual(outbound['settings']['vnext'][0]['users'][0],
                         {'id': '00000000-0000-4000-8000-000000000000', 'encryption': 'none', 'flow': 'xtls-rprx-vision'})
        self.assertEqual(outbound['streamSettings']['realitySettings'],
                         {'serverName': 'example.org', 'fingerprint': 'firefox', 'publicKey': 'A' * 43,
                          'shortId': '12ab', 'spiderX': '/hello'})

    def test_dns_direct_routing_has_no_general_bypass(self):
        profile = incy.profile(BASE)
        self.assertEqual(profile['outbounds'][0]['protocol'], 'vless')
        self.assertEqual(profile['routing']['domainStrategy'], 'AsIs')
        rules = profile['routing']['rules']
        self.assertEqual(rules[0], {'type': 'field', 'inboundTag': ['dns-query'], 'outboundTag': 'direct'})
        self.assertEqual(rules[1]['ip'], ['8.8.8.8/32', '1.1.1.1/32'])
        self.assertEqual(rules[1]['port'], '53')
        self.assertEqual(rules[2]['outboundTag'], 'dns-out')
        self.assertEqual(rules[2]['port'], '53')
        self.assertEqual({r['outboundTag'] for r in rules}, {'direct', 'dns-out'})

    def test_grpc_mapping_and_socks_ipv6(self):
        outbound = incy.profile(BASE + '&type=grpc&serviceName=hello')['outbounds'][0]
        self.assertEqual(outbound['streamSettings']['grpcSettings'], {'serviceName': 'hello', 'multiMode': False})
        outbound = incy.profile('socks://[2606:4700:4700::1111]:1080')['outbounds'][0]
        self.assertEqual(outbound['settings']['servers'], [{'address': '2606:4700:4700::1111', 'port': 1080}])

    def test_skip_unrepresentable_xray_semantics_and_duplicates(self):
        profiles, status = incy.build_subscription([BASE, BASE + '#second-label', BASE + '&type=ws',
                                                  BASE + '&alpn=h2', 'ss://invalid'])
        self.assertEqual(len(profiles), 1)
        self.assertEqual(status['skipped'], {'xray_reality_transport': 1, 'xray_reality_alpn': 1, 'invalid_uri': 1})

    def test_merge_rebuilds_json_from_fresh_nodes_and_expires_old_json(self):
        with tempfile.TemporaryDirectory() as folder, patch.object(common, 'OUT', Path(folder)):
            out = Path(folder)
            core = canonical_reality(BASE)
            (out / 'vless.txt').write_text(core + '#DE%20server\n')
            common.write_json(out / 'vless_state.json', {'nodes': {core: {'last_verified_at': common.timestamp()}}})
            common.merge()
            profiles = json.loads((out / 'incy.json').read_text())
            self.assertEqual(len(profiles), 1)
            self.assertEqual(common.load_json(out / 'combined_status.json')['incy']['published'], 1)
            self.assertEqual((out / 'all.txt').read_text(), core + '#DE%20server\n')
            expired = (datetime.now(timezone.utc) - timedelta(seconds=common.TTL + 1)).isoformat()
            common.write_json(out / 'vless_state.json', {'nodes': {core: {'last_verified_at': expired}}})
            common.merge()
            self.assertEqual(json.loads((out / 'incy.json').read_text()), [])
            self.assertEqual((out / 'all.txt').read_text(), '')
            auto = json.loads((out / 'xray-auto.json').read_text())
            self.assertEqual(len(auto), 1)
            self.assertFalse(any(o['protocol'] == 'vless' for o in auto[0]['outbounds']))


@unittest.skipUnless(shutil.which('xray'), 'xray is not installed')
class XrayConfig(unittest.TestCase):
    def test_generated_configs_with_real_xray(self):
        uris = [BASE, BASE + '&flow=xtls-rprx-vision', BASE + '&type=raw&sid=abcd',
                BASE + '&type=grpc&serviceName=test', 'socks://1.0.0.1:1080',
                'socks://[2606:4700:4700::1111]:1080']
        for uri in uris:
            with self.subTest(uri=uri), tempfile.TemporaryDirectory() as folder:
                path = Path(folder) / 'config.json'
                path.write_text(json.dumps(incy.profile(uri)))
                result = subprocess.run(['xray', 'run', '-test', '-config', str(path)],
                                        capture_output=True, text=True, timeout=5)
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
