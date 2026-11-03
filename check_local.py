"""Recheck published VLESS candidates on the network where Happ will run."""
import argparse
from collections import Counter
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
import shutil
import subprocess
import threading
import time
from urllib.parse import unquote

from subscription import write_json
from update_protocols import verify
from vless import canonical, Unsupported
from xray_auto import build_choices

SOURCE = 'https://raw.githubusercontent.com/rorythebreaker/proxy-subscription/main/public/vless.txt'


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, default=Path('happ-local.json'))
    args = parser.parse_args()
    for command in ('curl', 'xray'):
        if not shutil.which(command):
            parser.exit(1, f'Required on PATH: {command}\n')
    try:
        feed = subprocess.check_output(
            ['curl', '-q', '--noproxy', '*', '-fsS', '--max-time', '30', SOURCE],
            text=True, timeout=35)
    except (subprocess.SubprocessError, OSError):
        parser.exit(1, 'Could not download the candidate list.\n')
    names = {}
    for line in feed.splitlines():
        try:
            names.setdefault(canonical(line.strip()), unquote(line.partition('#')[2]) or 'VLESS')
        except (Unsupported, ValueError):
            continue
    if not names:
        parser.exit(1, 'The subscription currently contains no supported candidates.\n')

    slots = threading.BoundedSemaphore(1)
    def check(uri):
        return verify({'uri': uri}, time.monotonic() + 180, slots)

    passed = []
    counts = Counter()
    print(f'Checking {len(names)} candidates on this network', flush=True)
    with ThreadPoolExecutor(max_workers=4) as pool:
        for index, record in enumerate(pool.map(check, names), 1):
            status = record['status']
            counts[status] += 1
            if status == 'passed':
                passed.append(record)
            print(f'{index}/{len(names)}: {names[record["uri"]]} — {status}', flush=True)
    print(dict(counts))
    if not passed:
        parser.exit(1, 'No candidates passed. No new JSON was written.\n')
    passed.sort(key=lambda record: (-record['speed_mbps'], record['latency_ms']))
    write_json(args.output, build_choices([record['uri'] for record in passed], names))
    print(f'Import {args.output.resolve()} into Happ ({len(passed)} nodes + AUTO).')


if __name__ == '__main__':
    main()
