"""Check desktop startup with an isolated store, without touching a real user's keys."""
import argparse
from contextlib import nullcontext
import os
from pathlib import Path
import subprocess
import signal
import sys
import tempfile

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("executable")
parser.add_argument("--corrupt-index", action="store_true")
parser.add_argument("--store", type=Path, help="Use an existing synthetic store without deleting it.")
parser.add_argument("--legacy-process-only", action="store_true", help="For published older versions without a readiness signal only.")
arguments = parser.parse_args()
if arguments.store and arguments.corrupt_index:
    parser.error("Corrupt-index checks require a new temporary store.")
if arguments.store and not arguments.store.is_dir():
    parser.error("The synthetic store must already exist.")
executable = Path(arguments.executable).resolve(strict=True)
workspace = nullcontext(arguments.store.resolve()) if arguments.store else tempfile.TemporaryDirectory(prefix="pgputility-startup-")
with workspace as store, tempfile.TemporaryDirectory(prefix="pgputility-readiness-") as health:
    if arguments.corrupt_index:
        Path(store, "index.json").write_text("{broken", encoding="utf-8")
    ready = Path(health, "window-opened")
    environment = dict(os.environ, PGPUTILITY_KEY_STORE=str(store), PGPUTILITY_STARTUP_READY_FILE=str(ready))
    options = {}
    if os.name == "nt":
        startup = subprocess.STARTUPINFO()
        startup.dwFlags |= subprocess.STARTF_USESHOWWINDOW
        startup.wShowWindow = 0
        options = {"startupinfo": startup, "creationflags": subprocess.CREATE_NO_WINDOW}
    else:
        # AppImage extract-and-run can keep a child alive after its launcher exits.
        options = {"start_new_session": True}
    process = subprocess.Popen([str(executable)], env=environment, stdout=subprocess.PIPE, stderr=subprocess.PIPE, **options)
    try:
        stdout, stderr = process.communicate(timeout=10)
    except subprocess.TimeoutExpired:
        if os.name == "nt":
            process.kill()
        else:
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
        process.communicate(timeout=10)
        if not arguments.legacy_process_only and (not ready.is_file() or ready.read_text() != "ready"):
            raise SystemExit("The process stayed alive but its main window did not report that it opened.")
        if arguments.corrupt_index and not list(Path(store).glob("index.corrupt.*.json")):
            raise SystemExit("The corrupt index was not preserved during startup recovery.")
        print("Legacy process-liveness check passed." if arguments.legacy_process_only else "The main window opened and stayed alive with an isolated key store.")
    else:
        print(stdout.decode("utf-8", errors="replace"))
        print(stderr.decode("utf-8", errors="replace"), file=sys.stderr)
        raise SystemExit(f"The app exited early with code {process.returncode}.")
