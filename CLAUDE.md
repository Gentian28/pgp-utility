# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Commands

```bash
dotnet build PgpUtility.slnx                 # must end with 0 warnings, analyzers are on
dotnet test PgpUtility.slnx                  # ~71 tests, about 40 seconds
dotnet test PgpUtility.slnx --filter "FullyQualifiedName~GnuPgInterop"
dotnet run --project src/PgpUtility.App      # launch the app
python packaging/icon/make-icon.py           # regenerate every icon asset
```

Package versions live **only** in `Directory.Packages.props` (Central Package Management);
`TargetFramework`, nullable and analyzers live only in `Directory.Build.props`. Never add a
`Version=` attribute to a csproj. The App project overrides nothing except its own output type and
RIDs.

`PGPUTILITY_REQUIRE_GPG=1` turns a skipped GnuPG interoperability test into a failure. CI sets it
on Linux. `PGPUTILITY_KEY_STORE` overrides where keys are stored, which is how the screenshot
tooling avoids touching a real key store.

## What this app is

A local OpenPGP tool. Everything runs on the user's machine and nothing is sent anywhere. That is
the product position, not just an implementation detail, and it is shared with the sibling project
`Gentian28/resume-builder`.

**Keyserver upload and fetch are deliberately out of scope.** They put key material on the
network, which contradicts the above. Do not add them without an explicit decision to change the
positioning.

## Architecture

```
src/PgpUtility.Core/    net8.0, no UI dependency. Models/ and Services/.
src/PgpUtility.App/     Avalonia 11, MVVM via CommunityToolkit. WinExe, four RIDs.
src/PgpUtility.Tests/   xUnit + AwesomeAssertions. References Core only.
```

The test project references **Core only**, never App. App is a WinExe with a desktop toolkit, and
referencing it would pin the suite to one platform and defeat the three-platform CI matrix. Logic
worth testing therefore belongs in Core.

Composition happens in `App.axaml.cs`. The pickers and clipboard resolve the window lazily through
a `Func<TopLevel?>`, because they hang off the window and the view models are built before it
exists. No view model holds a window reference.

## Crypto invariants

These are the parts where a plausible-looking change is a real weakness. None are preferences.

- **AES-256 everywhere, not a parameter.** `PgpService.SessionCipher` is both the session cipher
  and the cipher protecting a secret key at rest. CAST5 was used for both until 2026-07-30; it has
  a 64-bit block that large files reach, and the key's own self-signature already advertised AES.
- **The integrity check is always on and is always verified.** `PgpEncryptedDataGenerator` gets
  `withIntegrityPacket: true`, and `DecryptCore` calls `pbe.Verify()`. Writing the MDC without
  checking it on the way back in buys nothing, which is exactly what the code did before. It was a
  caller-supplied bool; it must not become one again.
- **`Verify()` must be called while the encrypted stream is still open**, because it drains what
  is left of that stream to reach the trailing MDC packet. Moving it after the `using` silently
  stops it working.
- **`DecryptCore` streams into its output and throws afterwards on failure.** It cannot do
  otherwise: the check is only evaluable at the last byte, and buffering an arbitrary file is not
  an option. **The caller owns the cleanup.** The file path writes `<output>.partial` and moves it
  into place only on success; the text path discards a MemoryStream. Any new caller inherits that
  obligation.
- **Preferred algorithm lists are a promise to other people's software.** `ApplyCommonPreferences`
  advertises AES only, plus `Features.FEATURE_MODIFICATION_DETECTION`. Putting CAST5 or 3DES back
  invites a correspondent to encrypt to us with it.
- **Passphrases are `char[]`, never `string`, and are zeroed after use.** The service copies what
  it is given and clears its copy; view models clear theirs and raise `PassphraseCleared` so the
  view can empty its box. Defence in depth only: Avalonia's TextBox holds a managed string the app
  cannot zero, which is a real reduction from the WPF build's `SecurePassword` path, and the
  comments say so rather than implying more.
- **Passphrases are encoded UTF-8**, matching GnuPG. `PgpKeyRoles.ExtractPrivateKey` tries
  `ExtractPrivateKeyUtf8` first and falls back to BouncyCastle's older one-byte-per-char encoding.
  Shared by decryption, signing and revocation on purpose: three copies would drift, and the one
  that drifted would tell people to retype a passphrase that was already correct.
- **A bad passphrase and an unreadable file are different errors.** `IncorrectPassphraseException`
  and `IntegrityCheckFailedException` exist so the user is told which happened.
- **`SignatureVerification.Completed` is separate from `IsValid`.** "The signature does not match"
  and "we could not check" are different answers; collapsing them is how a failure gets reported
  as a valid signature.

## Things that are only true because they were tested against gpg

Testing our code against our code would keep passing if we invented our own dialect of OpenPGP.
These were all found that way:

- **A revocation certificate must be armored as `PGP PUBLIC KEY BLOCK`, not `PGP SIGNATURE`.**
  BouncyCastle labels armor from the packet type, so a bare signature comes out as `PGP
  SIGNATURE`, and gpg rejects that with "no valid OpenPGP data found" while the key stays live.
  `CreateRevocationCertificate` relabels the two header lines. The body and CRC are untouched.
- **Ed25519 uses `EdDsa_Legacy` (algorithm 22)**, which deployed GnuPG reads. The RFC 9580 Ed25519
  tag is newer than the tools.
- **Clear-signed text uses `CanonicalTextDocument` and strips trailing whitespace per line.** A
  message pasted into mail or chat has its line endings rewritten, and a binary-document signature
  would not survive it.

## Key generation shapes

Ed25519 and RSA generate differently on purpose:

- **Ed25519** produces a ring: an Ed25519 master that certifies and signs, plus a Curve25519 ECDH
  subkey that receives encryption. Ed25519 cannot encrypt, so the subkey is not optional.
- **RSA** is a single key that certifies, signs and encrypts. GnuPG would split this into a master
  and an encryption subkey, but that means generating two 4096-bit keys and roughly doubles an
  already slow wait. For Ed25519 both halves are effectively free, so it gets the conventional
  shape.

Revocation certificates are generated at creation, while the passphrase is in hand. Generating one
later needs the private key and passphrase, and losing either is the main reason to revoke.

## Key store

`KeyStoreLocation.Default()` picks the per-platform convention, including
`~/Library/Application Support` on macOS rather than the `~/.config` that .NET's `ApplicationData`
maps to there. Every write goes through `WriteIntoStoreAsync` or `CopyIntoStoreAsync` so there is
**one place** the file mode is applied: 0700 on the directory, 0600 on key files, including keys
copied in from a world-readable source and private keys exported to a folder the user chose.
Windows is left to its inherited ACL.

A route that wrote a key without going through those two would be world-readable on Unix and show
no symptom on Windows, which is why the tests for this only mean anything off Windows.

## UI notes

- **Avalonia's `DataContext` on an element also applies to that element's own bindings.** Putting
  `IsVisible="{Binding HasSelection}"` and `DataContext="{Binding SelectedKey}"` on one panel looks
  up `HasSelection` on `PgpKeyInfo` and fails the compiled-binding build.
- **The theme centres a TextBox by default**, so in a star-sized grid row it collapses to a
  one-line strip. `VerticalAlignment="Stretch"` plus `VerticalContentAlignment="Top"` is needed.
  Likewise `MaxWidth` with `HorizontalAlignment="Left"` shrinks an empty box to nothing; use
  `Width`.
- **`AutomationProperties.Name` on every TabItem.** Without it a screen reader announces the
  content's type name.
- Drag and drop uses `DataTransfer`, not the deprecated `Data`.

## Screenshots

Synthetic mouse clicks do not reach Avalonia on this setup. Drive the UI through UI Automation
(`SelectionItemPattern`) instead, capture with `DwmGetWindowAttribute` extended frame bounds rather
than `GetWindowRect` (which includes the invisible border and captures whatever is behind), and
point `PGPUTILITY_KEY_STORE` at a seeded scratch store so the shots show a populated app without
touching a real one. Screenshot identities are synthetic.

## Repo notes

- Before going public, re-run the check for committed key material, clean on 2026-07-30:
  `git log --all --name-only --format="" | sort -u | grep -iE "\.(asc|gpg|key|pem)$"`
- Never commit real key material or a real passphrase. Test keys are generated at run time.
- `Gentian28/resume-builder` is the reference for repo structure, CI, Velopack packaging and
  release asset naming. Read it before changing any of those rather than inventing a second
  convention.
- The release workflow requires a `## x.y.z` section in CHANGELOG.md before it will build.

## House rules

- **No em dashes anywhere**, including README, comments and commit messages. Use a comma, a colon
  or a full stop. Rewriting the sentence usually beats swapping the punctuation.
- Conventional Commits (`feat:`, `fix:`, `chore:`).
- Prefer evergreen phrasing over facts that go stale.
- Report what you could not verify instead of claiming a success you did not check.
- **A green build is not evidence the thing works.** For anything touching the crypto, say which
  you have: it compiled, or it round-tripped and gpg agreed. Those are different claims. The
  Avalonia port compiled cleanly and then died on startup because `DataGrid` needs its own
  package; only running it caught that.
