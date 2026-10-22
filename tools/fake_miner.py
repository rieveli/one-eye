"""HARMLESS fake cryptominer for running One Eye from source (the .exe has a built-in demo button).

It only burns CPU (mines nothing, connects nowhere) and stops by itself.

    python tools/fake_miner.py               # 60 s, uses half your CPU cores
    python tools/fake_miner.py --from-temp   # runs a copy from %TEMP%, so it also trips the
                                             # "suspicious folder" rule; the copy deletes itself
Press Ctrl+C to stop early.
"""
import argparse
import hashlib
import os
import shutil
import subprocess
import sys
import tempfile
import threading
import time


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--seconds", type=int, default=60)
    ap.add_argument("--from-temp", action="store_true")
    args = ap.parse_args()

    if args.from_temp:
        target = os.path.join(tempfile.gettempdir(), "miner_x.py")
        shutil.copy(__file__, target)
        print(f"Running from {target}")
        try:
            sys.exit(subprocess.call([sys.executable, target, "--seconds", str(args.seconds)]))
        finally:
            os.remove(target)

    stop = threading.Event()

    def burn():
        buf = os.urandom(1 << 20)
        while not stop.is_set():
            hashlib.sha256(buf).digest()   # releases the GIL, so threads use real cores

    for _ in range(max(1, (os.cpu_count() or 2) // 2)):
        threading.Thread(target=burn, daemon=True).start()   # threads die with the process: no orphans
    print(f"Fake miner: burning CPU for {args.seconds} s (harmless demo).")
    try:
        time.sleep(args.seconds)
    except KeyboardInterrupt:
        pass
    stop.set()
    print("Fake miner stopped.")


if __name__ == "__main__":
    main()
