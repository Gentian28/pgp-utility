# PGP Utility

A Windows desktop application for OpenPGP key management, encryption, and decryption.

## Features

- **Encrypt / Decrypt** — single files or batches, with progress reporting and cancellation
- **Key generation** — create new RSA key pairs with configurable size, identity, and passphrase
- **Key management** — import, export, and delete keys; importing a private key automatically extracts its public key

Keys are stored locally under `%APPDATA%\PgpUtility\Keys\` with an `index.json` manifest.

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
