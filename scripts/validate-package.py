"""Exercise real release packages on a fresh hosted runner with synthetic data only."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import shutil
import subprocess
import sys
import tempfile
import time
import urllib.request
import zipfile
import plistlib

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("--artifacts", required=True, type=Path)
parser.add_argument("--rid", required=True, choices=["win-x64", "linux-x64", "osx-arm64", "osx-x64"])
parser.add_argument("--fixture", required=True, type=Path)
parser.add_argument("--version", required=True, help="Expected centrally configured package version.")
args = parser.parse_args()
if os.environ.get("GITHUB_ACTIONS") != "true" or not os.environ.get("RUNNER_TEMP"):
    parser.error("Installer acceptance is restricted to fresh GitHub-hosted runners.")
expected_system = "Windows" if args.rid.startswith("win-") else "Darwin" if args.rid.startswith("osx-") else "Linux"
if platform.system() != expected_system:
    parser.error("The package must run on its native operating system.")
expected_machine = "arm64" if args.rid == "osx-arm64" else "x86_64"
if platform.machine().lower().replace("amd64", "x86_64") != expected_machine:
    parser.error("The package must run on its native architecture.")

artifacts = args.artifacts.resolve(strict=True)
fixture = args.fixture.resolve(strict=True)
repository = Path(__file__).resolve().parent.parent
workspace = Path(tempfile.mkdtemp(prefix="pgputility-package-", dir=os.environ["RUNNER_TEMP"]))
data = workspace / "synthetic"
environment = dict(os.environ, PGPUTILITY_KEY_STORE=str(data / "keys"))
channel = {"win-x64": "win", "linux-x64": "linux", "osx-arm64": "osx", "osx-x64": "osx-x64"}[args.rid]
report = {"rid": args.rid, "version": args.version, "previous_version": "1.1.0", "checks": []}


def run(command, timeout=120):
    subprocess.run([str(part) for part in command], env=environment, check=True, timeout=timeout)


def smoke(executable, existing=False, legacy=False):
    run([sys.executable, repository / "scripts/smoke-startup.py", executable,
         *(["--store", data / "keys"] if existing else []),
         *(["--legacy-process-only"] if legacy else [])], timeout=90)
    if not existing:
        run([sys.executable, repository / "scripts/smoke-startup.py", executable, "--corrupt-index"], timeout=90)


def stop_installer_launch():
    # These exact-name processes can only belong to this task on a fresh hosted runner.
    time.sleep(3)
    command = ["taskkill", "/F", "/IM", "PgpUtility.App.exe"] if expected_system == "Windows" else ["pkill", "-x", "PgpUtility.App"]
    subprocess.run(command, env=environment, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=30)


def previous_asset(name):
    previous = workspace / "previous"
    previous.mkdir(exist_ok=True)
    base = "https://github.com/Gentian28/pgp-utility/releases/download/v1.1.0/"
    checksum_path = previous / ("SHA256SUMS-" + channel + ".txt")
    urllib.request.urlretrieve(base + checksum_path.name, checksum_path)
    checksums = {}
    for line in checksum_path.read_text().splitlines():
        digest, filename = line.split(maxsplit=1)
        checksums[filename.lstrip("*")] = digest.lower()
    if name not in checksums:
        raise RuntimeError("The previous release does not declare this asset's checksum.")
    output = previous / name
    urllib.request.urlretrieve(base + name, output)
    with output.open("rb") as source:
        if hashlib.file_digest(source, "sha256").hexdigest() != checksums[name]:
            raise RuntimeError("The previous release asset does not match its published checksum.")
    return output


def find_mac_app(directory):
    matches = []
    for app in directory.glob("*.app"):
        with (app / "Contents/Info.plist").open("rb") as source:
            if plistlib.load(source).get("CFBundleExecutable") == "PgpUtility.App":
                matches.append(app)
    if len(matches) != 1:
        raise RuntimeError(f"Expected one PGP Utility bundle under {directory}, found {len(matches)}.")
    return matches[0]


def check_version(directory):
    # sq.version is the installed Velopack manifest, independent of the download's filename.
    import xml.etree.ElementTree as xml
    manifests = list(directory.rglob("sq.version"))
    if not manifests:
        raise RuntimeError("Installed Velopack version manifest is missing.")
    versions = [element.text for path in manifests for element in xml.parse(path).iter()
                if element.tag.rsplit("}", 1)[-1] == "version"]
    if args.version not in versions:
        raise RuntimeError(f"The application was not upgraded to {args.version}: {versions}")


def verify_new_checksums():
    lines = []
    for path in sorted(artifacts.iterdir()):
        if path.is_file() and not path.name.startswith(("SHA256SUMS", "acceptance-")):
            with path.open("rb") as source:
                lines.append(f"{hashlib.file_digest(source, 'sha256').hexdigest()}  {path.name}")
    checksum_file = artifacts / ("SHA256SUMS-" + channel + ".txt")
    checksum_file.write_text("\n".join(lines) + "\n", encoding="utf-8")
    for line in lines:
        digest, filename = line.split("  ", 1)
        with (artifacts / filename).open("rb") as source:
            if hashlib.file_digest(source, "sha256").hexdigest() != digest:
                raise RuntimeError("A packaged asset changed during validation.")


run(["dotnet", fixture, "seed", data])
if expected_system == "Windows":
    import winreg
    try:
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Uninstall\PgpUtility"):
            raise RuntimeError("Refusing to alter a pre-existing production installation.")
    except FileNotFoundError:
        pass
    if (Path(os.environ["LOCALAPPDATA"]) / "PgpUtility").exists():
        raise RuntimeError("Refusing to alter pre-existing production app files.")
    install = workspace / "installed"
    run([previous_asset("PgpUtility-win-Setup.exe"), "--silent", "--installto", install, "--log", workspace / "previous-install.log"])
    stop_installer_launch()
    executable = install / "current/PgpUtility.App.exe"
    smoke(executable, existing=True, legacy=True)
    report["checks"].append("previous published installer and legacy process-liveness check")
    run([artifacts / "PgpUtility-win-Setup.exe", "--silent", "--installto", install, "--log", workspace / "upgrade-install.log"])
    stop_installer_launch()
    check_version(install / "current")
    smoke(executable, existing=True)
    smoke(executable)
    report["checks"].append("production-ID setup upgrade, populated/empty/corrupt-index startup")
    run(["dotnet", fixture, "verify", data])
    run([install / "Update.exe", "--silent", "--rootDir", install, "--log", workspace / "uninstall.log", "uninstall"])
    if executable.exists():
        raise RuntimeError("Uninstall left the application executable behind.")
    if not (data / "keys").is_dir():
        raise RuntimeError("Uninstall removed the synthetic key store outside the installation.")
    report["checks"].append("historical access, migration, restore and uninstall without store loss")
    portable = workspace / "portable"
    with zipfile.ZipFile(artifacts / "PgpUtility-win-Portable.zip") as archive:
        archive.extractall(portable)
    matches = list(portable.rglob("PgpUtility.App.exe"))
    if len(matches) != 1:
        raise RuntimeError("Expected one portable application executable.")
    smoke(matches[0])
    report["checks"].append("extracted portable empty/corrupt-index startup")
elif expected_system == "Darwin":
    applications = Path("/Applications")
    if any((app / "Contents/MacOS/PgpUtility.App").exists() for app in applications.glob("*.app")):
        raise RuntimeError("Refusing to alter a pre-existing PGP Utility installation.")
    run(["sudo", "installer", "-pkg", previous_asset(f"PgpUtility-{channel}-Setup.pkg"), "-target", "/"])
    stop_installer_launch()
    app = find_mac_app(applications)
    smoke(app / "Contents/MacOS/PgpUtility.App", existing=True, legacy=True)
    report["checks"].append("previous published pkg and legacy process-liveness check")
    run(["sudo", "installer", "-pkg", artifacts / f"PgpUtility-{channel}-Setup.pkg", "-target", "/"])
    stop_installer_launch()
    app = find_mac_app(applications)
    check_version(app)
    smoke(app / "Contents/MacOS/PgpUtility.App", existing=True)
    smoke(app / "Contents/MacOS/PgpUtility.App")
    run(["dotnet", fixture, "verify", data])
    report["checks"].append("production-ID pkg upgrade, startup, historical access, migration and restore")
    portable = workspace / "portable"
    run(["ditto", "-x", "-k", artifacts / f"PgpUtility-{channel}-Portable.zip", portable])
    smoke(find_mac_app(portable) / "Contents/MacOS/PgpUtility.App")
    report["checks"].append("portable bundle empty/corrupt-index startup")
else:
    # Extract-and-run executes the delivered AppImage on runners without a FUSE mount.
    environment["APPIMAGE_EXTRACT_AND_RUN"] = "1"
    installed = workspace / "PgpUtility.AppImage"
    shutil.copyfile(previous_asset("PgpUtility.AppImage"), installed)
    installed.chmod(0o755)
    smoke(installed, existing=True, legacy=True)
    shutil.copyfile(artifacts / "PgpUtility.AppImage", installed)
    installed.chmod(0o755)
    smoke(installed, existing=True)
    smoke(installed)
    run(["dotnet", fixture, "verify", data])
    report["checks"].append("previous AppImage legacy process check; current window-open startup, historical access, migration and restore")

verify_new_checksums()
report["checks"].append("packaged asset checksums")
report["result"] = "passed"
(artifacts / f"acceptance-{args.rid}.json").write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
print(json.dumps(report, indent=2))
