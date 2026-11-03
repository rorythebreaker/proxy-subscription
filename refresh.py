#!/usr/bin/env python3
"""Build a complete snapshot in isolation; never keep failed nodes as fallback."""
from concurrent.futures import ThreadPoolExecutor
import json
import os
from pathlib import Path
import shutil
import signal
import subprocess
import sys
import tempfile

import subscription as common


def run_stage(script, staged, timeout):
    process = subprocess.Popen([sys.executable, script],
        env=dict(os.environ, OUTPUT_DIR=str(staged)), start_new_session=True)
    try:
        return process.wait(timeout=timeout)
    except subprocess.TimeoutExpired:
        os.killpg(process.pid, signal.SIGKILL)
        process.wait()
        return -1


def main():
    common.OUT.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix='subscription-') as folder:
        staged = Path(folder) / 'public'
        staged.mkdir()
        for name in ('vless_state.json', 'socks5.json'):
            previous = common.OUT / name
            if previous.exists():
                shutil.copy2(previous, staged / name)
        with ThreadPoolExecutor(max_workers=2) as pool:
            vless = pool.submit(run_stage, 'update_protocols.py', staged,
                                int(os.getenv('VLESS_STAGE_SECONDS', '280')))
            socks = pool.submit(run_stage, 'refresh_socks.py', staged,
                                int(os.getenv('SOCKS_STAGE_SECONDS', '300')))
            code, socks_code = vless.result(), socks.result()
        status = common.load_json(staged / 'status.json')
        if code != 0 or not status.get('published_at'):
            common.publish([], {'error': 'collector_timeout' if code == -1 else 'collector_failed',
                                'strict_current_run': True})
        else:
            for path in staged.iterdir():
                if path.is_file() and path.name != 'socks5.json' and not path.name.endswith('.tmp'):
                    common.atomic_write(common.OUT / path.name, path.read_text())
            for obsolete in ('socks_state.json', 'shadowsocks.txt'):
                (common.OUT / obsolete).unlink(missing_ok=True)

        socks_profiles = []
        socks_path = staged / 'socks5.json'
        if socks_code == 0 and socks_path.exists():
            socks_profiles = json.loads(socks_path.read_text())
        vless_profiles = json.loads((common.OUT / 'xray-auto.json').read_text())
        common.write_json(common.OUT / 'socks5.json', socks_profiles)
        common.write_json(common.OUT / 'subscription.json', vless_profiles + socks_profiles)
        common.write_json(common.OUT / 'combined_status.json', {
            'published_at': common.timestamp(),
            'counts': dict(common.load_json(common.OUT / 'status.json').get('counts', {}),
                           socks5=len(socks_profiles)),
            'socks_exit_code': socks_code,
        })


if __name__ == '__main__':
    main()
