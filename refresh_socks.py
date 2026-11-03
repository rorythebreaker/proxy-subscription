"""Build a separate SOCKS5 subscription from the current network."""
import base64
from collections import Counter
from concurrent.futures import ThreadPoolExecutor
import ipaddress
import json
import os
import re
import subprocess
import time
from urllib.parse import urlsplit

import subscription as common
from incy import base_profile

ADVANCED = 'https://advanced.name/ru/freeproxy?type=socks5'
SOURCES = (
    ADVANCED,
    'https://raw.githubusercontent.com/proxifly/free-proxy-list/main/proxies/protocols/socks5/data.txt',
    'https://raw.githubusercontent.com/monosans/proxy-list/main/proxies/socks5.txt',
    'https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/socks5.txt',
)


def advanced_rows(data):
    endpoints = []
    for row in re.findall(rb'<tr\b[^>]*>(.*?)</tr\s*>', data, re.I | re.S):
        if not re.search(rb'>\s*SOCKS5\s*<', row, re.I):
            continue
        fields = [re.search(rb'data-' + field + rb'="([^"]+)"', row)
                  for field in (b'ip', b'port')]
        if all(fields):
            try:
                host, port = [base64.b64decode(field[1], validate=True).decode('ascii')
                              for field in fields]
                host = '[' + host + ']' if ':' in host else host
                endpoints.append(f'{host}:{port}'.encode('ascii'))
            except ValueError:
                continue
    if not endpoints:
        raise ValueError('No SOCKS5 rows found in Advanced.name')
    return b'\n'.join(endpoints)


def candidates(data):
    for line in data.decode('utf-8', errors='replace').splitlines():
        line = line.strip()
        try:
            endpoint = urlsplit(line if '://' in line else 'socks5://' + line)
            if endpoint.scheme != 'socks5' or endpoint.username is not None:
                continue
            address = ipaddress.ip_address(endpoint.hostname)
            port = endpoint.port
            if address.is_global and not address.is_multicast and port:
                yield address, port
        except (ValueError, TypeError):
            continue


def check(endpoint):
    address, port = endpoint
    host = f'[{address}]' if address.version == 6 else str(address)
    proxy = f'socks5h://{host}:{port}'
    for target in common.TARGETS:
        latency = common.probe(proxy, target)
        if latency is not None and latency <= common.MAX_LATENCY_MS:
            break
    else:
        return 'https_failed', None

    for _ in range(2):
        speed = common.measure_speed(proxy)
        if speed is not None and speed >= common.MIN_SPEED_MBPS:
            remote = {'tag': 'proxy', 'protocol': 'socks',
                      'settings': {'servers': [{'address': str(address), 'port': port}]}}
            profile = base_profile([], {'outboundTag': 'proxy'})
            profile['outbounds'].insert(0, remote)
            profile['remarks'] = f'SOCKS5 | {host}:{port}'
            return 'passed', (speed, latency, profile)
    return 'speed_unconfirmed', None


def previous_endpoints():
    try:
        profiles = json.loads((common.OUT / 'socks5.json').read_text())
    except (OSError, ValueError):
        return []
    endpoints = []
    for profile in profiles if isinstance(profiles, list) else []:
        try:
            server = profile['outbounds'][0]['settings']['servers'][0]
            address = ipaddress.ip_address(server['address'])
            port = server['port']
            if address.is_global and not address.is_multicast and type(port) is int and 0 < port <= 65535:
                endpoints.append((address, port))
        except (KeyError, IndexError, TypeError, ValueError):
            continue
    return endpoints


def main():
    deadline = time.monotonic() + int(os.getenv('SOCKS_STAGE_SECONDS', '300')) - 5
    previous = previous_endpoints()
    endpoints = {}
    available_sources = 0
    for source in SOURCES:
        try:
            data = common.fetch_bytes(source)
            if source == ADVANCED:
                data = advanced_rows(data)
            available_sources += 1
            for endpoint in candidates(data):
                endpoints.setdefault(endpoint, None)
        except (ValueError, OSError, subprocess.SubprocessError):
            print(f'Source unavailable: {source}', flush=True)
    # Rotate the batch so successive runs test different addresses.
    ordered = list(endpoints)
    if ordered:
        offset = (int(time.time()) // 300 * 600) % len(ordered)
        ordered = (ordered[offset:] + ordered[:offset])
    ordered = list(dict.fromkeys(previous + ordered))[:600]

    def check_with_budget(endpoint):
        # Two HTTPS probes and two speed downloads may take around 46 seconds.
        if time.monotonic() + 50 >= deadline:
            return 'not_tested', None
        return check(endpoint)

    with ThreadPoolExecutor(max_workers=24) as pool:
        results = list(pool.map(check_with_budget, ordered))
    passed = [item for status, item in results if status == 'passed']
    print(f'SOCKS5 outcomes: {dict(Counter(status for status, _ in results))}', flush=True)
    passed.sort(key=lambda item: (-item[0], item[1]))
    common.write_json(common.OUT / 'socks5.json', [item[2] for item in passed])
    print(f'SOCKS5: {len(passed)} passed out of {len(ordered)} selected.')
    if not available_sources and not previous:
        raise SystemExit('All SOCKS5 sources are unavailable')


if __name__ == '__main__':
    main()
