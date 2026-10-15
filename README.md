# PGP Utility

A desktop app for OpenPGP: generate keys, encrypt and decrypt files and text, sign and verify.
Windows, macOS and Linux.

Everything happens on your machine. There is no account, no telemetry, and no keyserver: your
keys are never sent anywhere, because there is nowhere for them to be sent.

![The Keys tab, showing a key's fingerprint and details](docs/screenshots/04-keys.png)

## Why this exists

This is for occasional OpenPGP tasks: you have a file or message and a public key, and want
clear local controls for completing the exchange. It shows which fingerprint was used, preserves
existing files, and distinguishes an invalid signature from a check it could not perform.

It is a sibling to [resume-builder](https://github.com/Gentian28/resume-builder), and shares its
position: a real desktop application that runs entirely on your machine and sends nothing
anywhere.

## What it does

- **Files.** Encrypt and decrypt, one file or a batch, with progress and cancellation. Drag and
  drop onto the window.
- **Text.** Encrypt, decrypt, sign and verify a block of text, which is what most PGP is actually
  used for. Pasting an encrypted or signed block selects the matching action.
- **Sign and verify.** Detached signatures, so the original file is untouched and someone without
  this tool can still open it. Clear-signed blocks for text.
- **Keys.** Generate Ed25519 or RSA, import, export, search. Fingerprints are grouped so you can
  actually compare them by eye. Back up and restore the store, extend expiry, change passphrases,
  and save or apply revocation certificates. Deletion requires confirmation of the selected fingerprint.

| Files | Text | Sign and verify |
|---|---|---|
| ![Files tab](docs/screenshots/01-files.png) | ![Text tab](docs/screenshots/02-text.png) | ![Sign and verify tab](docs/screenshots/03-sign-verify.png) |

## Cryptography

- **AES-256**, always. Not a setting.
- **Every message carries an integrity check, and decryption verifies it.** A file that fails is
  rejected and produces no output at all. This is what stops someone who cannot read your
  plaintext from flipping chosen bits in it.
- **Ed25519** by default, with a Curve25519 encryption subkey. RSA is available at 2048 or 4096
  bits for older tooling.
- **Revocation certificates** are generated when you create a key. Publishing one retires a key
  you have lost access to, and it cannot be created later, because creating it needs the private
  key and passphrase you would have lost.
- Keys are stored per-platform, and on macOS and Linux the key directory is `0700` and key files
  are `0600`. New sensitive files use owner-only Windows ACLs from creation.
- Passphrases are held as character arrays and cleared after use. This narrows the window in which
  a passphrase sits in memory. It is not protection against a machine that is already compromised.

Encryption and signing interoperability with GnuPG are tested in both directions. CI runs the
suite on Windows, macOS and Linux. GnuPG checks are mandatory on Linux; other platforms can
skip them if their GnuPG agent is unavailable.

**This project has not been independently audited.** See [SECURITY.md](SECURITY.md).

## Install

On Windows, winget is the shortest route:

```
winget install Gentian28.PgpUtility
```

The winget index may trail a new GitHub release while its submission is reviewed. Compare the
installed version in the app footer with the release you intended to use.

Otherwise download from the [latest release](https://github.com/Gentian28/pgp-utility/releases/latest).

| Platform | File |
|---|---|
| Windows | `PgpUtility-win-Setup.exe`, or `PgpUtility-win-Portable.zip` for no installer |
| macOS (Apple silicon) | `PgpUtility-osx-Setup.pkg` |
| macOS (Intel) | `PgpUtility-osx-x64-Setup.pkg` |
| Linux | `PgpUtility.AppImage` |

Nothing needs to be installed alongside it. The .NET runtime is bundled.

### The scary warning you are about to see

**The downloads are not code-signed.** A signing certificate costs a few hundred a year, and this
is a free tool. Unsigned is not the same as unsafe, but it does mean your operating system will
warn you, and hiding that would be worse than explaining it.

**Windows** shows a blue "Windows protected your PC" box. Click **More info**, then **Run anyway**.

**macOS** refuses on first launch, with "cannot be opened because the developer cannot be
verified". Either:

- Right-click (or Control-click) the app, choose **Open**, then **Open** again in the dialog. The
  right-click matters: double-clicking gives you no Open button.
- Or open **System Settings**, go to **Privacy & Security**, scroll to the bottom, and click
  **Open Anyway** next to the message about PGP Utility.

**Linux** does not warn, but the AppImage needs the executable bit:

```bash
chmod +x PgpUtility.AppImage
./PgpUtility.AppImage
```

Minimal Linux systems also need Fontconfig and the X11 session libraries. On Debian or Ubuntu,
install `libfontconfig1 libice6 libsm6 libx11-6` through your system package manager before launching.

### Verifying a download

Each release includes `SHA256SUMS-<platform>.txt`. Compare the hash of the exact file you downloaded:

```bash
sha256sum -c SHA256SUMS-win.txt        # Linux
shasum -a 256 -c SHA256SUMS-osx.txt    # macOS
```

```powershell
Get-FileHash PgpUtility-win-Setup.exe -Algorithm SHA256   # Windows, compare by eye
```

For builds that include GitHub artifact attestations, also follow the
[release verification guide](docs/release-verification.md). Checksums detect corruption; an
attestation ties a file to the repository build. Neither replaces platform code signing.

### Code signing

An application to the [SignPath Foundation](https://signpath.org/) free code-signing programme
was declined in August 2026. The programme requires public adoption signals (stars, forks,
independent references) that a newly published project does not yet have, and it will be
reapplied for once the project has them. Until then the warnings above apply and the checksums
remain available.

## Where your keys are stored

| Platform | Location |
|---|---|
| Windows | `%APPDATA%\PgpUtility\Keys` |
| macOS | `~/Library/Application Support/PgpUtility/Keys` |
| Linux | `$XDG_DATA_HOME/pgputility/keys`, or `~/.local/share/pgputility/keys` |

Set `PGPUTILITY_KEY_STORE` to put them somewhere else, such as a removable drive.

## Safe first use

Follow the [first exchange and recovery guide](docs/first-use.md). See the
[compatibility limits](docs/compatibility.md) before importing keys from another tool.

The screenshots above show the last released interface. The approved safety and recovery UI is
in [the design record](design/safety-and-recovery.html); visual verification is pending.

## Build from source

Requires the [.NET 10 SDK](https://dotnet.microsoft.com/download/dotnet/10.0).

```bash
dotnet build PgpUtility.slnx
dotnet test PgpUtility.slnx
dotnet run --project src/PgpUtility.App
```

The GnuPG interoperability tests skip if `gpg` is not on your PATH. Set `PGPUTILITY_REQUIRE_GPG=1`
to turn a skip into a failure, which is what CI does.

## Project layout

```
src/PgpUtility.Core/    Models, services and toolkit-neutral view models. No desktop dependency, so it is what the tests target.
src/PgpUtility.App/     Avalonia 11 desktop UI, MVVM via CommunityToolkit.
src/PgpUtility.Tests/   xUnit. Round trips, failure modes, permissions, GnuPG interoperability.
packaging/icon/         Icon sources, all generated by make-icon.py.
```

## License

[MIT](LICENSE)
