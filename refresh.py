#!/usr/bin/env python3
"""Build a complete snapshot in isolation; never keep failed nodes as fallback."""
import os
from pathlib import Path
import shutil
import signal
import subprocess
import sys
import tempfile

import subscription as common


def main():
    common.OUT.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix='subscription-') as folder:
        staged = Path(folder) / 'public'
        staged.mkdir()
        previous = common.OUT / 'vless_state.json'
        if previous.exists():
            shutil.copy2(previous, staged / previous.name)
        process = subprocess.Popen([sys.executable, 'update_protocols.py'],
            env=dict(os.environ, OUTPUT_DIR=str(staged)), start_new_session=True)
        try:
            code = process.wait(timeout=int(os.getenv('VLESS_STAGE_SECONDS', '280')))
        except subprocess.TimeoutExpired:
            os.killpg(process.pid, signal.SIGKILL)
            process.wait()
            code = -1
        status = common.load_json(staged / 'status.json')
        if code != 0 or not status.get('published_at'):
            common.publish([], {'error': 'collector_timeout' if code == -1 else 'collector_failed',
                                'strict_current_run': True})
        else:
            for path in staged.iterdir():
                if path.is_file() and not path.name.endswith('.tmp'):
                    common.atomic_write(common.OUT / path.name, path.read_text())
            for obsolete in ('socks_state.json', 'shadowsocks.txt'):
                (common.OUT / obsolete).unlink(missing_ok=True)


if __name__ == '__main__':
    main()
