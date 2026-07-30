# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Commands

```bash
dotnet build PgpUtility.slnx                              # must end with 0 warnings
dotnet run --project src/PgpUtility/PgpUtility.csproj     # launch the app
```

There is no test project yet. When one lands it goes in `src/PgpUtility.Tests` and the commands
above gain a `dotnet test PgpUtility.slnx`.

## What this app is

A local OpenPGP tool: generate keys, encrypt, decrypt, manage a small key store. Everything runs
on the user's machine and nothing is sent anywhere. That is the product position, not just an
implementation detail, and it is shared with the sibling project `Gentian28/resume-builder`.

**Keyserver upload and fetch are deliberately out of scope.** They put key material on the
network, which contradicts the above. Do not add them without an explicit decision to change the
positioning.

## Architecture

One WPF project, `src/PgpUtility`, on `net8.0-windows`, MVVM via CommunityToolkit
(`[ObservableProperty]` / `[RelayCommand]`).

- **Models/** plain data objects. No UI dependency.
- **Services/** `PgpService` (all BouncyCastle work), `KeyStoreService` (the on-disk key store),
  `FileDialogService` (the one WPF-bound service).
- **ViewModels/** one per tab, coordinated by `MainViewModel`, which owns the shared log.
- **Views/** XAML user controls plus their code-behind.

`Models/` and `Services/` have no UI dependency apart from `FileDialogService`, which is what
makes them testable without a UI and portable to another toolkit. Keep it that way: nothing under
those two folders should reference `System.Windows` except `FileDialogService`.

Two view models reach around the abstraction and should be fixed when they are next touched:
`KeyGenerationViewModel.SaveKeysAsync` news up a `FileDialogService` directly instead of taking
the injected `IFileDialogService`, and both `KeyGenerationViewModel` and `KeyManagementViewModel`
call `System.Windows.Clipboard` from the view model.

## Crypto invariants

These are the parts where a plausible-looking change is a real weakness. None of them are
preferences.

- **AES-256 everywhere, and it is not a parameter.** `PgpService.SessionCipher` is the session key
  cipher and the cipher protecting a secret key at rest. CAST5 was used for both until 2026-07-30;
  it has a 64-bit block, which is a birthday bound a large file can reach, and the key's own
  self-signature was advertising AES the whole time.
- **The integrity check is always on and is always verified.** `PgpEncryptedDataGenerator` is
  constructed with `withIntegrityPacket: true`, and `Decrypt` calls `pbe.Verify()`. Writing the
  MDC without checking it on the way back in buys nothing, which is what the code did before. It
  was a caller-supplied bool; it is not one any more, and it should not become one again. Without
  it an OpenPGP message is malleable: an attacker who cannot read the plaintext can still flip
  chosen bits in it.
- **`Verify()` has to be called while the encrypted stream is still open**, because it drains what
  is left of that stream to reach the trailing MDC packet. Moving it after the `using` block
  silently stops it working.
- **Decryption writes to `<output>.partial` and moves the file into place only after the integrity
  check passes.** A failed check must leave no output at all, not a file that is deleted a moment
  later.
- **Preferred algorithm lists are a promise to other people's software.** `ApplyCommonPreferences`
  advertises AES only, plus `Features.FEATURE_MODIFICATION_DETECTION`. Adding CAST5 or 3DES back
  to that list invites a correspondent to encrypt to us with it.
- **Passphrases are `char[]`, never `string`, and are zeroed after use.** The service copies the
  array it is given and clears its copy; view models clear theirs and raise `PassphraseCleared` so
  the view can empty its password box. `PasswordBoxExtensions.ReadPassphrase` goes through
  `SecurePassword` specifically so that reading `PasswordBox.Password` never mints one immutable
  string per keystroke. This is defence in depth. It shortens the window and cuts the number of
  copies; it does nothing against an attacker who can already read the process, and it cannot stop
  the page reaching swap. Say so, rather than implying the passphrase is protected.
- **Passphrases are encoded UTF-8**, matching GnuPG. `ExtractPrivateKey` tries
  `ExtractPrivateKeyUtf8` first and falls back to BouncyCastle's older one-byte-per-char encoding
  so keys written that way still open. The two are identical for ASCII and differ beyond it.
- **A bad passphrase and an unreadable file are different errors.** `IncorrectPassphraseException`
  and `IntegrityCheckFailedException` exist so the user is told which one happened. Mapping every
  `PgpException` to one message sends people round in circles.

## Key generation shapes

Ed25519 and RSA generate differently on purpose, and the asymmetry is deliberate:

- **Ed25519** produces a ring: an Ed25519 master that certifies and signs, plus a Curve25519 ECDH
  subkey that receives encryption. Ed25519 cannot encrypt, so the subkey is not optional. The tag
  is `EdDsa_Legacy` (algorithm 22), which is what deployed GnuPG reads; the RFC 9580 Ed25519 tag is
  newer than the tools.
- **RSA** is a single key that certifies, signs and encrypts. GnuPG would split this into a master
  and an encryption subkey, but that means generating two 4096-bit keys and roughly doubles an
  already slow wait. For Ed25519 both halves are effectively free, so it gets the conventional
  shape.

Verified on 2026-07-30 against GnuPG 2.2.41: gpg reads a generated key as `ed25519 [SC]` plus
`cv25519 [E]`, encrypts to it, and our ciphertext has the same packet shape as gpg's own output
(tag 1 algo 18, tag 18 with `mdc_method`).

## Repo notes

- The repo is private and unreleased. Before it goes public, re-run the check for committed key
  material, which was clean on 2026-07-30:
  `git log --all --name-only --format="" | sort -u | grep -iE "\.(asc|gpg|key|pem)$"`
- Never commit real key material or a real passphrase. Test fixtures are generated at test time.
- `Gentian28/resume-builder` is the reference for repo structure, CI, Velopack packaging and
  release asset naming. Read it before changing any of those here rather than inventing a second
  convention.

## House rules

- **No em dashes anywhere**, including README, comments and commit messages. Use a comma, a colon
  or a full stop. Rewriting the sentence usually beats swapping the punctuation.
- Conventional Commits (`feat:`, `fix:`, `chore:`).
- Prefer evergreen phrasing over facts that go stale.
- Report what you could not verify instead of claiming a success you did not check.
- **A green build is not evidence the thing works.** For anything touching `PgpService`, say which
  you have: it compiled, or it round-tripped and a tampered ciphertext was rejected. Those are
  different claims.
