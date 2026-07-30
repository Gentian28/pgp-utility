# PGP Utility

A Windows desktop application for OpenPGP key management, encryption, and decryption.

## Features

- **Encrypt / decrypt**: single files or batches, with progress reporting and cancellation
- **Key generation**: Ed25519 with a Curve25519 encryption subkey, or RSA at 2048 or 4096 bits
- **Key management**: import, export, and delete keys. Importing a private key automatically
  extracts its public key

Keys are stored locally under `%APPDATA%\PgpUtility\Keys\` with an `index.json` manifest. Nothing
is sent anywhere: there is no keyserver upload or fetch, by design.

## Cryptography

- Files are encrypted with **AES-256**, and that is not a setting.
- Every message carries a **modification detection code**, and decryption verifies it before the
  plaintext reaches its destination. A file that fails the check produces no output. This is what
  stops an attacker who cannot read your plaintext from flipping chosen bits in it.
- Keys interoperate with GnuPG. Verified against GnuPG 2.2 in both directions.
- Passphrases are held as `char[]` and zeroed once used rather than left as strings for the
  garbage collector. This is defence in depth: it shortens the window in which a passphrase sits
  in memory. It is not protection against an attacker who can already read the process.

This project has not been independently audited.

## Requirements

- Windows
- [.NET 8.0 SDK](https://dotnet.microsoft.com/download/dotnet/8.0) (to build) or the .NET 8 Desktop Runtime (to run)

## Build & Run

```bash
dotnet build
dotnet run --project src/PgpUtility/PgpUtility.csproj
```

## Tech stack

- WPF on `net8.0-windows`, MVVM architecture
- [BouncyCastle.Cryptography](https://www.bouncycastle.org/) for OpenPGP operations
- [CommunityToolkit.Mvvm](https://learn.microsoft.com/dotnet/communitytoolkit/mvvm/) source generators

## Project layout

```
src/PgpUtility/
  Models/       Plain data objects
  Services/     PGP, key store, and file dialog services
  ViewModels/   One view model per tab, coordinated by MainViewModel
  Views/        XAML user controls
  Resources/    Colors and styles
```

## License

[MIT](LICENSE)
