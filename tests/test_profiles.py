import json
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest
from copy import deepcopy
from incy import profile, connection_digest
from xray_auto import build_auto, build_choices
from test_vless import REALITY, xhttp

class Profiles(unittest.TestCase):
    def test_all_individual_nodes_are_shown_with_no_limit(self):
        uris = [REALITY + '&sid=' + f'{i:02x}' for i in range(70)] + [xhttp()]
        choices = build_choices(uris)
        self.assertEqual(len(choices), 72)
        self.assertEqual(len([o for o in choices[0]['outbounds'] if o['protocol'] == 'vless']), 24)
        for uri, manual in zip(uris, choices[1:]):
            self.assertEqual(manual, profile(uri))
            self.assertEqual(manual['routing']['balancers'], [])
            self.assertFalse(any(o['protocol'] == 'socks' for o in manual['outbounds']))

    def test_verified_and_exported_profiles_differ_only_by_local_ports_and_name(self):
        for uri in (REALITY, xhttp()):
            exported = profile(uri, 'rank / measured speed')
            verified = deepcopy(exported)
            verified['remarks'] = 'test'
            verified['inbounds'][0]['port'] = 41001
            verified['inbounds'][1]['port'] = 41002
            self.assertEqual(connection_digest(exported), connection_digest(verified))
            verified['dns']['servers'] = ['9.9.9.9']
            self.assertNotEqual(connection_digest(exported), connection_digest(verified))

    def test_auto_uses_identical_outbound_settings_without_socks_fallback(self):
        for uri in (REALITY, xhttp()):
            auto = build_auto([uri])
            remote = next(o for o in auto['outbounds'] if o['protocol'] == 'vless')
            expected = deepcopy(profile(uri)['outbounds'][0])
            expected['tag'] = remote['tag']
            self.assertEqual(remote, expected)
            self.assertEqual(auto['routing']['balancers'][0]['fallbackTag'], 'block')
            self.assertFalse(any(o['protocol'] in ('socks', 'loopback') for o in auto['outbounds']))
        empty = build_auto([])
        self.assertNotIn('burstObservatory', empty)
        self.assertEqual(empty['routing']['rules'][-1]['outboundTag'], 'block')

    def test_dns_interception_covers_tun_and_probe_targets_are_not_direct(self):
        rules = profile(REALITY)['routing']['rules']
        dns = next(r for r in rules if r.get('outboundTag') == 'dns-out')
        self.assertNotIn('inboundTag', dns)
        self.assertEqual(rules[-1]['outboundTag'], 'proxy')
        direct = [r for r in rules if r.get('outboundTag') == 'direct']
        self.assertFalse(any('domain:cloudflare.com' in r.get('domain', []) or 'domain:gstatic.com' in r.get('domain', []) for r in direct))
        self.assertTrue(all(r.get('port') == '53' for r in direct if '8.8.8.8' in r.get('ip', [])))

    @unittest.skipUnless(shutil.which('xray'), 'xray not installed')
    def test_pinned_xray_accepts_all_modes_and_empty_auto(self):
        configs = [build_auto([]), profile(REALITY + '&flow=xtls-rprx-vision')]
        for mode in ('auto', 'packet-up', 'stream-up', 'stream-one'):
            configs.extend(build_choices([xhttp(mode=mode, extra='{"noGRPCHeader":true}')]))
        for config in configs:
            with tempfile.TemporaryDirectory() as folder:
                p = Path(folder) / 'config.json'
                p.write_text(json.dumps(config))
                result = subprocess.run(['xray', 'run', '-test', '-config', str(p)], capture_output=True, timeout=5)
                self.assertEqual(result.returncode, 0, result.stdout.decode() + result.stderr.decode())
