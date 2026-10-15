"""Check desktop startup with an isolated store, without touching a real user's keys."""
import os
from pathlib import Path
import subprocess
import sys
import tempfile

executable = Path(sys.argv[1]).resolve(strict=True)
with tempfile.TemporaryDirectory(prefix="pgputility-startup-") as store:
    if "--corrupt-index" in sys.argv[2:]:
        Path(store, "index.json").write_text("{broken", encoding="utf-8")
    environment = dict(os.environ, PGPUTILITY_KEY_STORE=store)
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
        if "--corrupt-index" in sys.argv[2:] and not list(Path(store).glob("index.corrupt.*.json")):
            raise SystemExit("The corrupt index was not preserved during startup recovery.")
        print("The app stayed alive through the startup check with an isolated key store.")
    else:
        print(stdout.decode("utf-8", errors="replace"))
        print(stderr.decode("utf-8", errors="replace"), file=sys.stderr)
        raise SystemExit(f"The app exited early with code {process.returncode}.")
