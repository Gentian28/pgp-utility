# Compatibility and limits

PGP Utility generates v4 Ed25519 legacy algorithm 22 keys with a Curve25519 ECDH encryption subkey,
or a combined RSA key at 2048 or 4096 bits. New message encryption uses AES-256, compression and
an integrity packet. New signatures use SHA-256. Keys, signatures and ciphertext are compared with
GnuPG in the test suite; this is interoperability evidence, not an independent security audit.

GnuPG linked against libgcrypt 1.12.0, the version Ubuntu 26.04 ships, can refuse a Curve25519
secret key with "Bad passphrase" when the passphrase is correct. A self-test in that libgcrypt
reads past the end of a buffer, so the outcome depends on memory contents; libgcrypt 1.12.1 fixed
it (upstream T8080). It appears on the first decryption or export after `gpg --batch --import`,
and is not specific to keys from this app. Importing without `--batch`, so that gpg asks for the
passphrase during the import, avoided it in testing. The GnuPG comparisons in CI run on Ubuntu
24.04 until 26.04 has the fix.

Import one identity per file. Binary and armored public or secret exports are supported. A named
identity needs a valid primary self-certification, and every subkey needs a valid binding. Signing
subkeys also need cross-certification. Critical requirements the app cannot interpret are rejected.
Direct-key-only certificates, key collections, smartcard operations, designated external revokers,
and automatic trust or key discovery are outside the supported profile. v6 keys, AEAD messages and
other newer formats are not claimed as supported merely because a dependency can parse them.

Reimport and restore keep existing private packets and their current passphrase protection while
adding new subkeys and public certifications. Only Change passphrase replaces protection of an
existing private packet. Restore into an empty store to recover access using an older backup passphrase.

New encryption and signing require an unrevoked, unexpired authorized key. Expired or revoked
private keys can still decrypt historical messages. Historical signatures can be mathematically
good while carrying an expiry or revocation warning. This app does not reconstruct the entire
certificate history at the time of signing or independently authenticate claimed signature times.
Keep and compare the signer's full primary fingerprint.

Document verification supports SHA-224, SHA-256, SHA-384 and SHA-512 digests. Legacy digests such as
SHA-1 and MD5 produce an unavailable-verification result. Use a specialist tool to investigate
unsupported historical material. Older key self-certifications may use legacy digests; independent
review of certificate policy remains a release requirement for broad trust claims.

Text and individual imported key or signature files are limited to 16 MiB. Decrypted text also has
a 16 MiB expansion limit. File encryption and decryption stream large files. Compression nesting is
limited to 16 layers. Backup restore accepts at most 4096 entries, 16 MiB per entry and 64 MiB total
expanded content. Unsupported input leaves existing files intact.

The store index is a cache, rebuilt from validated key files. A corrupt index is preserved. Named
mutexes serialize cooperating instances, but transactions across several key files are not a
power-loss journal. A tested offline backup remains necessary. Missing or unsupported key files
are preserved and reported in the local log.

Sensitive staging and newly committed files are created with owner-only access. That does not
protect an already compromised user account, clipboard history, old exported copies, or unmanaged
string copies held by the UI. Decrypted files are committed only after processing succeeds; legacy
messages without integrity protection carry an explicit warning.

Development requires the .NET 10 SDK pinned by global.json. Downloads bundle their runtime. CI
builds on Windows, Linux and macOS and publishes win-x64, linux-x64, osx-arm64 and osx-x64. A local
Windows check does not establish that the other three native packages run.
