import json
import unittest
from urllib.parse import urlencode
from vless import canonical, outbound, transport

REALITY = 'vless://00000000-0000-4000-8000-000000000000@8.8.8.8:443?security=reality&sni=example.org&pbk=' + 'A' * 43

def xhttp(**kwargs):
    q = {'type': 'xhttp', 'security': 'tls', 'sni': 'example.org', 'fp': 'edge', 'alpn': 'h2', 'host': 'cdn.example.org', 'path': '/upload/', 'mode': 'stream-up', **kwargs}
    return 'vless://00000000-0000-4000-8000-000000000000@8.8.8.8:443?' + urlencode(q)

class Validation(unittest.TestCase):
    def test_only_requested_transports_and_public_endpoints(self):
        for suffix in ('&type=ws', '&type=grpc', '&type=httpupgrade', '&type=xhttp'):
            with self.assertRaises(ValueError): canonical(REALITY + suffix)
        for uri in ('socks://8.8.8.8:443', REALITY.replace('8.8.8.8', '127.0.0.1'), REALITY.replace('8.8.8.8', 'localhost'), REALITY.replace(':443?', ':65536?'), REALITY.replace('00000000-0000-4000-8000-000000000000', 'bad'), REALITY + '&security=tls', REALITY + '&sid=abc', REALITY + '&alpn=h2', REALITY + '&unknown=1', REALITY + '&allowInsecure=1', '\n' + REALITY, REALITY.replace('A' * 43, 'A' * 42), None):
            with self.subTest(uri=uri), self.assertRaises(ValueError): canonical(uri)
        self.assertEqual(transport(REALITY + '&type=raw'), 'tcp_reality')
        self.assertEqual(transport(xhttp()), 'xhttp_tls')

    def test_canonical_equivalence_and_preserved_credentials(self):
        uri = REALITY + '&sid=ABCD&flow=xtls-rprx-vision&spx=%2Fhello'
        core = canonical(uri)
        self.assertEqual(core, canonical(core + '#different-label'))
        self.assertEqual(core, canonical(uri + '&fp=chrome&type=tcp&encryption=none'))
        o = outbound(uri)
        self.assertEqual(o['settings']['vnext'][0]['users'][0]['flow'], 'xtls-rprx-vision')
        self.assertEqual(o['streamSettings']['realitySettings']['shortId'], 'abcd')
        self.assertEqual(o['streamSettings']['realitySettings']['spiderX'], '/hello')
        self.assertIn('@[2606:4700:4700::1111]:443?', canonical(REALITY.replace('8.8.8.8', '[2606:4700:4700::1111]')))

    def test_xhttp_extra_and_tls_settings_are_lossless(self):
        extra = {'noGRPCHeader': True, 'xmux': {'maxConcurrency': 6}, 'downloadSettings': {'address': 'example.net', 'port': 443, 'network': 'xhttp', 'security': 'tls', 'tlsSettings': {'serverName': 'example.net'}, 'xhttpSettings': {'path': '/upload/'}}}
        o = outbound(xhttp(extra=json.dumps(extra)))
        self.assertEqual(o['streamSettings']['xhttpSettings']['extra'], extra)
        self.assertEqual(o['streamSettings']['tlsSettings'], {'serverName': 'example.org', 'fingerprint': 'edge', 'alpn': ['h2']})
        self.assertNotIn('dialerProxy', o['streamSettings']['sockopt'])
        for params in ({'extra': '[]'}, {'extra': '{bad'}, {'extra': '{"x":NaN}'}, {'mode': 'invalid'}, {'path': 'missing-slash'}, {'flow': 'xtls-rprx-vision'}, {'insecure': 'true'}):
            with self.subTest(params=params), self.assertRaises(ValueError): canonical(xhttp(**params))
