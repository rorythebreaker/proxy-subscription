"""XHTTP parameters, engine routing, freshness and Xray config compatibility."""
import json
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock, patch
from urllib.parse import urlencode

import subscription as common
import update_protocols as vless
from incy import build_subscription, proxy_outbound
from xray_auto import build_choices
from test_subscription import BASE


def link(**params):
    q = {'security': 'tls', 'type': 'xhttp', 'sni': 'example.org',
         'host': 'cdn.example.org', 'path': '/storage/upload/session',
         'mode': 'stream-up', 'fp': 'edge', 'alpn': 'h2', **params}
    return 'vless://00000000-0000-4000-8000-000000000000@8.8.8.8:443?' + urlencode(q)


class XHTTP(unittest.TestCase):
    def test_preserves_tls_transport_extra_in_manual_and_auto(self):
        extra = {'noGRPCHeader': True, 'noSSEHeader': True,
                 'xmux': {'maxConcurrency': 6, 'hMaxRequestTimes': '150-250'}}
        uri = link(extra=json.dumps(extra))
        self.assertFalse(vless.valid_reality(uri))
        canonical = vless.canonical_vless(uri)
        self.assertEqual(canonical, vless.canonical_vless(canonical))
        profiles, info = build_subscription([uri])
        self.assertEqual(info['published'], 1)
        self.assertIn('XHTTP TLS', profiles[0]['remarks'])
        for config in [profiles[0], *build_choices([uri])]:
            outbound = next(o for o in config['outbounds'] if o['protocol'] == 'vless')
            stream = outbound['streamSettings']
            self.assertEqual(stream['network'], 'xhttp')
            self.assertEqual(stream['tlsSettings'], {'serverName': 'example.org', 'fingerprint': 'edge', 'alpn': ['h2']})
            self.assertEqual(stream['xhttpSettings'], {'host': 'cdn.example.org', 'path': '/storage/upload/session', 'mode': 'stream-up', 'extra': extra})
            self.assertNotIn('dialerProxy', stream['sockopt'])

    def test_unknown_or_insecure_or_invalid_parameters_are_not_silently_dropped(self):
        for q in ({'extra': '[]'}, {'extra': '{bad'}, {'mode': 'unknown'},
                  {'flow': 'xtls-rprx-vision'}, {'allowInsecure': '1'},
                  {'insecure': 'true'}, {'path': 'no-slash'}, {'unknown': 'option'}):
            with self.subTest(q=q):
                self.assertEqual(build_subscription([link(**q)])[0], [])
        self.assertEqual(len(build_subscription([link(allowInsecure='0', insecure='false')])[0]), 1)

    def test_mixed_collection_reserves_room_for_xhttp(self):
        body = ('\n'.join([BASE + '&sid=' + f'{i:02x}' for i in range(50)] + [link()])).encode()
        with patch.object(vless, 'SOURCES', {'vless_reality': ['source']}), patch.object(vless, 'MAX_ITEMS', 2), patch.object(vless, 'fetch_bytes', return_value=body):
            uris, sources = vless.collect()
        self.assertEqual(sources, 1)
        self.assertEqual(len(uris), 2)
        self.assertTrue(any(vless.parse_vless(u)[2]['security'] == 'tls' for u in uris))
        crowded = [BASE + '&sid=' + f'{i:02x}' for i in range(30)] + [link()]
        auto = build_choices(crowded)[0]
        self.assertTrue(any(o.get('streamSettings', {}).get('network') == 'xhttp' for o in auto['outbounds']))

    def test_xray_verifier_runs_both_checks_inside_local_tunnel_and_reaps(self):
        process = Mock()
        process.poll.return_value = None
        sock = Mock()
        sock.__enter__ = Mock(return_value=sock)
        sock.__exit__ = Mock(return_value=None)
        sock.getsockname.return_value = ('127.0.0.1', 12345)
        sock.connect_ex.return_value = 0
        with patch.object(vless.socket, 'socket', return_value=sock), patch.object(vless.subprocess, 'run', return_value=Mock(returncode=0)) as check, patch.object(vless.subprocess, 'Popen', return_value=process) as start, patch.object(vless, 'connectivity', return_value=('passed', 1000)), patch.object(vless, 'filter_quality', return_value=('speed_rejected', 1000)) as quality:
            self.assertEqual(vless.verify(link(), common.TARGETS, baseline_ok=True)[1], 'speed_rejected')
            self.assertEqual(check.call_args.args[0][:3], ['xray', 'run', '-test'])
            self.assertEqual(start.call_args.args[0][:3], ['xray', 'run', '-config'])
            self.assertEqual(quality.call_args.args[0], 'socks5h://127.0.0.1:12345')
        process.terminate.assert_called_once()
        process.wait.assert_called_once()

    def test_merge_exports_fresh_xhttp_then_expires_it(self):
        uri = vless.canonical_vless(link())
        with tempfile.TemporaryDirectory() as folder, patch.object(common, 'OUT', Path(folder)):
            common.write_json(Path(folder) / 'vless_state.json', {'nodes': {uri: {'last_verified_at': common.timestamp(), 'quality_policy': common.QUALITY_POLICY}}})
            common.atomic_write(Path(folder) / 'vless.txt', uri + '\n')
            common.merge()
            self.assertEqual(len(json.loads((Path(folder) / 'incy.json').read_text())), 1)
            with patch.object(common, 'TTL', -1):
                common.merge()
            self.assertEqual(json.loads((Path(folder) / 'incy.json').read_text()), [])

    @unittest.skipUnless(shutil.which('xray'), 'xray is not installed')
    def test_real_xray_accepts_every_supported_mode_and_extra(self):
        for mode in ('auto', 'stream-up', 'stream-one', 'packet-up'):
            uri = link(mode=mode, extra=json.dumps({'noGRPCHeader': True, 'xmux': {'maxConcurrency': 6}}))
            for config in build_choices([uri]):
                with tempfile.TemporaryDirectory() as folder:
                    path = Path(folder) / 'config.json'
                    path.write_text(json.dumps(config))
                    result = subprocess.run(['xray', 'run', '-test', '-config', str(path)], capture_output=True, timeout=5)
                    self.assertEqual(result.returncode, 0, result.stdout.decode() + result.stderr.decode())
