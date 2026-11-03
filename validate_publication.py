"""Reject mismatched, stale or unverified generated subscriptions before commit."""
import json
from pathlib import Path
import subprocess
import tempfile

import subscription as c
from incy import connection_digest, profile
from vless import canonical, node_id
from xray_auto import build_auto


def validate(root):
    root = Path(root)
    read = lambda name: json.loads((root / name).read_text())
    nodes = read('vless_state.json')['nodes']
    ranked = sorted(nodes, key=lambda u: (-nodes[u]['speed_mbps'], nodes[u]['latency_ms'], node_id(u)))
    assert all(c.valid_record(u, nodes[u]) for u in ranked), 'unverified or stale record'
    manual = read('incy.json')
    assert len(manual) == len(ranked)
    for uri, config in zip(ranked, manual):
        assert config == profile(uri, config['remarks']), 'profile differs from verified template'
        assert connection_digest(config) == nodes[uri]['config_digest']
    automatic = build_auto(ranked)
    assert read('xray-auto.json') == [automatic] + manual
    assert read('xray-auto-only.json') == automatic
    assert read('status.json')['published'] == len(ranked)
    assert [n['id'] for n in read('servers.json')] == [node_id(u) for u in ranked]
    assert [n['speed_mbps'] for n in read('servers.json')] == [nodes[u]['speed_mbps'] for u in ranked]
    for name in ('all.txt', 'vless.txt'):
        assert [canonical(line) for line in (root / name).read_text().splitlines()] == ranked
    for name in ('alive.txt', 'proxies.txt'):
        assert not (root / name).read_text().strip(), 'legacy SOCKS nodes remain'
    socks = read('socks5.json')
    assert all(p['outbounds'][0]['protocol'] == 'socks' for p in socks)
    assert read('combined_status.json')['counts']['socks5'] == len(socks)
    assert read('subscription.json') == [automatic] + manual + socks
    for config in [automatic] + manual + socks:
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / 'profile.json'
            path.write_text(json.dumps(config))
            result = subprocess.run(['xray', 'run', '-test', '-config', str(path)], capture_output=True, timeout=10)
            assert result.returncode == 0, 'Xray rejected generated profile'
    print(f'Validated AUTO and {len(ranked)} individually verified, speed-ranked profiles')


if __name__ == '__main__':
    validate(c.OUT)
