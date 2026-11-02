import base64
import json
import subprocess
import tempfile
import time
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import Mock, patch

import subscription as common
import update as socks
import update_protocols as vless
import refresh

BASE = 'vless://00000000-0000-4000-8000-000000000000@8.8.8.8:443?security=reality&sni=example.org&pbk=' + 'A' * 43


class URIValidation(unittest.TestCase):
    def test_bad_credentials_key_port_and_shortid(self):
        for uri in (BASE.replace('00000000-0000-4000-8000-000000000000', 'nonsense'),
                    BASE.replace('A' * 43, 'bad'), BASE + '&sid=nothex', BASE + '&sid=abc',
                    BASE + '&sid=' + '12' * 9, BASE.replace(':443?', ':65536?'),
                    BASE + '&sni=other.org', BASE.replace('8.8.8.8', '127.0.0.1')):
            with self.subTest(uri=uri):
                self.assertFalse(vless.valid_reality(uri))

    def test_default_utls_and_optional_empty_shortid(self):
        outbound = vless.as_outbound(BASE)
        self.assertEqual(outbound['tls']['utls'], {'enabled': True, 'fingerprint': 'chrome'})
        self.assertEqual(outbound['tls']['reality']['short_id'], '')
        self.assertIn('fp=chrome', vless.canonical_reality(BASE))

    def test_canonical_dedup_preserves_transport_credentials_and_ipv6(self):
        first = BASE + '&type=ws&host=cdn.example.org&path=%2Fa%3Fb%3D1#label'
        other = BASE + '&path=%2Fa%3Fb%3D1&host=cdn.example.org&type=ws#other'
        self.assertEqual(vless.canonical_reality(first), vless.canonical_reality(other))
        self.assertEqual(vless.as_outbound(first)['transport']['path'], '/a?b=1')
        self.assertIn('@[2606:4700:4700::1111]:443?', vless.canonical_reality(BASE.replace('8.8.8.8', '[2606:4700:4700::1111]')))

    def test_transport_mapping_and_unsupported_not_dead(self):
        for transport, expected in [('ws', 'ws'), ('grpc', 'grpc'), ('h2', 'http'), ('httpupgrade', 'httpupgrade')]:
            self.assertEqual(vless.as_outbound(BASE + '&type=' + transport)['transport']['type'], expected)
        for suffix in ('&type=xhttp', '&encryption=unsupported', '&headerType=http', '&type=tcp&path=%2Ffoo'):
            self.assertEqual(vless.verify(BASE + suffix, common.TARGETS)[1], 'unsupported')

    def test_socks_uri_and_ipv6(self):
        self.assertEqual(common.canonical_socks('socks5://8.8.8.8:1080#US'), 'socks://8.8.8.8:1080')
        self.assertEqual(common.canonical_socks('[2606:4700:4700::1111]:1080'), 'socks://[2606:4700:4700::1111]:1080')
        for value in ('127.0.0.1:1080', '8.8.8.8:0', 'ss://8.8.8.8:1080', 'socks://user:pass@8.8.8.8:1080'):
            with self.assertRaises((ValueError, TypeError)):
                common.canonical_socks(value)


class Collection(unittest.TestCase):
    def test_base64_urlsafe_and_plain_with_long_comment(self):
        self.assertEqual(common.decode_lines(base64.urlsafe_b64encode(BASE.encode()).rstrip(b'=')), [BASE])
        self.assertIn(BASE, common.decode_lines(('#' * 2200 + '\n' + BASE).encode()))
        with self.assertRaises(ValueError):
            common.decode_lines(b'<html>outage</html>')

    def test_global_cap_and_source_diversity(self):
        def fetch(url):
            return ('\n'.join(BASE.replace('8.8.8.8', f'node{i}.{url}.example.org') for i in range(3))).encode()
        with patch.object(vless, 'SOURCES', {'vless_reality': ['one', 'two', 'three']}), patch.object(vless, 'MAX_ITEMS', 2), patch.object(vless, 'fetch_bytes', side_effect=fetch):
            nodes, success = vless.collect()
        self.assertEqual(success, 3)
        self.assertEqual(len(nodes), 2)
        self.assertIn('one.example.org', nodes[0])
        self.assertIn('two.example.org', nodes[1])

    def test_html_and_http_200_garbage_are_not_success(self):
        with patch.object(vless, 'fetch_bytes', return_value=b'<html>maintenance</html>'):
            self.assertEqual(vless.collect(), ([], 0))
        with patch.object(socks, 'fetch_bytes', return_value=b'<html>maintenance</html>'):
            self.assertEqual(socks.collect(), ([], 0))
        with patch.object(vless, 'fetch_bytes', return_value=b''):
            self.assertEqual(vless.collect()[1], len(vless.SOURCES['vless_reality']))


class Connectivity(unittest.TestCase):
    def test_second_target_can_rescue_proxy(self):
        with patch.object(common, 'probe', side_effect=[('network_error', None), ('passed', 9999)]):
            self.assertEqual(common.connectivity('socks5h://local', common.TARGETS), ('passed', 9999))

    def test_both_fail_vs_http_block_or_unhealthy_baseline(self):
        with patch.object(common, 'probe', return_value=('network_error', None)):
            self.assertEqual(common.connectivity('proxy', common.TARGETS)[0], 'unreachable')
        with patch.object(common, 'probe', side_effect=[('inconclusive', None), ('network_error', None)]):
            self.assertEqual(common.connectivity('proxy', common.TARGETS)[0], 'inconclusive')
        with patch.object(common, 'probe') as probe:
            self.assertEqual(common.connectivity('proxy', common.TARGETS[:1])[0], 'inconclusive')
            probe.assert_not_called()

    def test_total_download_deadline_and_size_limit(self):
        with patch.object(common.subprocess, 'run', return_value=Mock(returncode=0, stdout=b'ok')) as run:
            self.assertEqual(common.fetch_bytes('https://example.org', 100), b'ok')
            args = run.call_args.args[0]
            self.assertIn('--max-time', args)
            self.assertIn('--max-filesize', args)
            self.assertEqual(run.call_args.kwargs['timeout'], 13)

    def test_config_error_and_missing_binary_separate_from_dead(self):
        with patch.object(vless.subprocess, 'run', return_value=Mock(returncode=1, stderr=b'invalid configuration')):
            self.assertEqual(vless.verify(BASE, common.TARGETS)[1], 'config_error:other')
        with patch.object(vless.subprocess, 'run', side_effect=FileNotFoundError):
            self.assertEqual(vless.verify(BASE, common.TARGETS)[1], 'inconclusive')
        self.assertEqual(vless.verify(BASE, common.TARGETS, time.monotonic() - 1)[1], 'not_tested')

    def test_vless_has_no_latency_or_bandwidth_gate_and_reaps_process(self):
        process = Mock()
        process.poll.return_value = None
        sock = Mock()
        sock.__enter__ = Mock(return_value=sock)
        sock.__exit__ = Mock(return_value=None)
        sock.getsockname.return_value = ('127.0.0.1', 12345)
        sock.connect_ex.return_value = 0
        with patch.object(vless.socket, 'socket', return_value=sock), patch.object(vless.subprocess, 'run', return_value=Mock(returncode=0)), patch.object(vless.subprocess, 'Popen', return_value=process), patch.object(vless, 'connectivity', return_value=('passed', 12000)):
            self.assertEqual(vless.verify(BASE, common.TARGETS)[1:], ('passed', 12000))
        process.terminate.assert_called_once()
        process.wait.assert_called_once()


class Publication(unittest.TestCase):
    def setUp(self):
        self.folder = tempfile.TemporaryDirectory()
        self.out = Path(self.folder.name)
        self.patcher = patch.object(common, 'OUT', self.out)
        self.patcher.start()
        self.geo = patch.object(common, 'country_labels', side_effect=lambda uris: {uri: ('ZZ', 'example.org') for uri in uris})
        self.geo.start()

    def tearDown(self):
        self.geo.stop()
        self.patcher.stop()
        self.folder.cleanup()

    def test_recent_fallback_not_renewed_and_dead_removed(self):
        now = common.timestamp()
        core = vless.canonical_reality(BASE)
        old = {core: {'last_verified_at': now}}
        status, nodes = common.publish('vless', 'vless.txt', [(core, 'inconclusive', None)], old, 0, {'last_success_at': now}, {'fallback_reason': 'source outage'})
        self.assertEqual(status['published'], 1)
        self.assertEqual(status['new_count'], 0)
        self.assertTrue(status['stale'])
        self.assertEqual(nodes[core]['last_verified_at'], now)
        status, nodes = common.publish('vless', 'vless.txt', [(core, 'unreachable', None)], old, 0, {}, {})
        self.assertEqual(status['published'], 0)
        self.assertEqual(common.lines(self.out / 'vless.txt'), [])

    def test_expired_cache_cannot_be_republished(self):
        expired = (datetime.now(timezone.utc) - timedelta(seconds=common.TTL + 10)).isoformat()
        core = vless.canonical_reality(BASE)
        status, nodes = common.publish('vless', 'vless.txt', [(core, 'inconclusive', None)], {core: {'last_verified_at': expired}}, 0, {}, {})
        self.assertEqual(nodes, {})

    def test_merge_dedup_filters_wrong_protocol_expired_and_legacy(self):
        core = vless.canonical_reality(BASE)
        common.publish('vless', 'vless.txt', [(core, 'passed', None)], {}, 1, {}, {})
        with (self.out / 'vless.txt').open('a') as file:
            file.write(core + '#duplicate\nss://garbage\n' + BASE.replace('8.8.8.8', '1.1.1.1') + '\n')
        (self.out / 'shadowsocks.txt').write_text('legacy')
        common.merge()
        self.assertEqual(len(common.lines(self.out / 'all.txt')), 1)
        self.assertEqual(common.lines(self.out / 'vless.txt'), common.lines(self.out / 'all.txt'))
        self.assertFalse((self.out / 'shadowsocks.txt').exists())
        self.assertEqual(common.load_json(self.out / 'protocol_status.json')['vless_reality']['published'], 1)

    def test_failed_stage_does_not_publish_partial_output(self):
        (self.out / 'vless.txt').write_text('previous\n')
        process = Mock()
        process.wait.return_value = 1
        with patch.object(refresh, 'OUT', self.out), patch.object(refresh.subprocess, 'Popen', return_value=process):
            self.assertFalse(refresh.run_stage('update_protocols.py', 1))
        self.assertEqual((self.out / 'vless.txt').read_text(), 'previous\n')
        self.assertTrue(common.load_json(self.out / 'protocol_status.json')['vless_reality']['stale'])


if __name__ == '__main__':
    unittest.main()
