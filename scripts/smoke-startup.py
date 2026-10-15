"""Check desktop startup with an isolated store, without touching a real user's keys."""
import argparse
from contextlib import nullcontext
import os
from pathlib import Path
import subprocess
import sys
import tempfile

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("executable")
parser.add_argument("--corrupt-index", action="store_true")
parser.add_argument("--store", type=Path, help="Use an existing synthetic store without deleting it.")
arguments = parser.parse_args()
if arguments.store and arguments.corrupt_index:
    parser.error("Corrupt-index checks require a new temporary store.")
if arguments.store and not arguments.store.is_dir():
    parser.error("The synthetic store must already exist.")
executable = Path(arguments.executable).resolve(strict=True)
workspace = nullcontext(arguments.store.resolve()) if arguments.store else tempfile.TemporaryDirectory(prefix="pgputility-startup-")
with workspace as store:
    if arguments.corrupt_index:
        Path(store, "index.json").write_text("{broken", encoding="utf-8")
    environment = dict(os.environ, PGPUTILITY_KEY_STORE=str(store))
    options = {}
    if os.name == "nt":
        startup = subprocess.STARTUPINFO()
        startup.dwFlags |= subprocess.STARTF_USESHOWWINDOW
        startup.wShowWindow = 0
        options = {"startupinfo": startup, "creationflags": subprocess.CREATE_NO_WINDOW}
    process = subprocess.Popen([str(executable)], env=environment, stdout=subprocess.PIPE, stderr=subprocess.PIPE, **options)
    try:
        stdout, stderr = process.communicate(timeout=10)
    except subprocess.TimeoutExpired:
        process.kill()
        process.communicate(timeout=10)
        if arguments.corrupt_index and not list(Path(store).glob("index.corrupt.*.json")):
            raise SystemExit("The corrupt index was not preserved during startup recovery.")
        print("The app stayed alive through the startup check with an isolated key store.")
    else:
        print(stdout.decode("utf-8", errors="replace"))
        print(stderr.decode("utf-8", errors="replace"), file=sys.stderr)
        raise SystemExit(f"The app exited early with code {process.returncode}.")
