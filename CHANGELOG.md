# Changelog

## 1.1.0

- **Theme choice.** A System / Light / Dark selector in the status bar. The default follows the
  operating system's mode, and the choice is remembered between runs.
- **The window keeps itself on screen.** On a scaled display the default window size could exceed
  the screen, and centring it then pushed the title bar off the top edge, leaving the window
  impossible to move, minimise or close. The window now shrinks to the working area and centres
  inside it.

## 1.0.0

First public release. Cross-platform, and a substantial rework of the cryptography since the
Windows-only version.

### Encryption

- Files and text are encrypted with **AES-256**. Earlier builds used CAST5, which has a 64-bit
  block that large files can push past its safe limit.
- Every message carries an integrity check, and **decryption now verifies it**. Previously the
  check was written but never validated, so a modified file decrypted without complaint. A file
  that fails the check produces no output at all.
- Encrypted output is written to a temporary file and only moved into place once the check passes.

### Keys

- **Ed25519** keys with a Curve25519 encryption subkey, generated in milliseconds. RSA is still
  available and now defaults to 4096 bits.
- **Revocation certificates** are produced when a key is created and can be saved alongside it.
  Publishing one retires a key you can no longer use. It is generated up front because making one
  later needs the private key and its passphrase, and losing those is the usual reason to need it.
- Optional expiry dates on new keys.
- Keys are stored per-platform: `%APPDATA%` on Windows, `~/Library/Application Support` on macOS
  and `$XDG_DATA_HOME` on Linux. On macOS and Linux the key directory is `0700` and key files are
  `0600`.

### New in this release

- **Sign and verify.** Detached signatures for files, clear-signed blocks for text. The original
  file is left untouched.
- **Text mode.** Encrypt, decrypt, sign and verify a block of text without going through a file.
  Pasting an encrypted or signed block selects the matching action.
- **Drag and drop** files onto the window.

### Interoperability

Verified against GnuPG in both directions on Windows, macOS and Linux: keys generated here import
into gpg, gpg encrypts to them, and gpg reads what this app produces.

### Notes

- Passphrases are held in memory as character arrays and cleared after use. This narrows the
  window in which a passphrase is resident; it is not protection against a compromised machine.
- Nothing is code-signed, so Windows shows a SmartScreen warning and macOS shows a Gatekeeper
  one. The README explains the exact steps.
- This project has not been independently audited.
