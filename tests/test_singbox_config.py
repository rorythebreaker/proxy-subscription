"""Offline integration check against the pinned sing-box binary (no proxy traffic)."""
import json
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

import update_protocols as vless


@unittest.skipUnless(shutil.which('sing-box'), 'sing-box is not installed')
class SingBoxConfig(unittest.TestCase):
    def test_supported_transports_and_default_utls(self):
        base = ('vless://00000000-0000-4000-8000-000000000000@8.8.8.8:443'
                '?security=reality&sni=example.org&pbk=' + 'A' * 43)
        for suffix in ('&type=tcp', '&type=ws&path=%2Fws&host=example.org',
                       '&type=grpc&serviceName=test', '&type=h2&path=%2Fh2&host=example.org',
                       '&type=httpupgrade&path=%2Fup&host=example.org',
                       '&type=tcp&flow=xtls-rprx-vision&alpn=h2%2Chttp%2F1.1'):
            with self.subTest(suffix=suffix), tempfile.TemporaryDirectory() as folder:
                path = Path(folder) / 'config.json'
                path.write_text(json.dumps(vless.config_for(vless.as_outbound(base + suffix), 12345)))
                result = subprocess.run(['sing-box', 'check', '-c', str(path)], capture_output=True, text=True, timeout=5)
                self.assertEqual(result.returncode, 0, result.stderr)
