#!/usr/bin/env python3
"""Stage each protocol independently; publish a consistent snapshot after both attempts."""
import os
import shutil
import signal
import subprocess
import sys
import tempfile
from pathlib import Path

from subscription import OUT, load_json, merge, timestamp, write_json


def run_stage(script, seconds):
    OUT.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="subscription-") as folder:
        staged = Path(folder) / "public"
        shutil.copytree(OUT, staged)
        env = dict(os.environ, OUTPUT_DIR=str(staged.resolve()))
        process = subprocess.Popen([sys.executable, script], env=env, start_new_session=True)
        try:
            code = process.wait(timeout=seconds)
        except subprocess.TimeoutExpired:
            # Kill the entire group, including curl/sing-box children.
            os.killpg(process.pid, signal.SIGKILL)
            process.wait()
            code = -1
        if code == 0:
            # The repository is committed only after merge(), so clients see one git snapshot.
            for path in staged.iterdir():
                if path.is_file() and not path.name.endswith(".tmp"):
                    shutil.copy2(path, OUT / path.name)
        else:
            name = "status.json" if script == "update.py" else "protocol_status.json"
            status = load_json(OUT / name)
            target = status if script == "update.py" else status.setdefault("vless_reality", {})
            target.update(attempted_at=timestamp(), stale=True,
                          fallback_reason="stage deadline exceeded" if code == -1 else "stage failed",
                          new_count=0)
            write_json(OUT / name, status)
            print(f"{script}: failed ({code}); retaining only unexpired verified cache", flush=True)
        return code == 0


def main():
    run_stage("update.py", int(os.getenv("SOCKS_STAGE_SECONDS", "120")))
    run_stage("update_protocols.py", int(os.getenv("VLESS_STAGE_SECONDS", "200")))
    merge()


if __name__ == "__main__":
    main()
