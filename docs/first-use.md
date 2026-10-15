# First exchange and recovery

PGP Utility works locally. You exchange files or text with your correspondent using a channel you
choose. The app does not upload keys, fetch identities, or establish trust in a name.

## Receive an encrypted message

1. On Generate, enter your name and a strong passphrase, confirm it and choose an expiry if needed.
2. Generate the key and add it to the store. Share only the public key.
3. Compare your full fingerprint with your correspondent over a separate channel you trust.
4. Ask for a small test message. Select your private key on Text or Files and decrypt it.
5. Back up before relying on the key for anything you cannot afford to lose.

## Send an encrypted message

1. Import the recipient's public key on Keys.
2. Compare the full fingerprint with the recipient over a trusted channel. A matching name or
   short key ID is insufficient.
3. Select the recipient on Text or Files and encrypt a test message. Have them confirm receipt.

Encryption does not identify the sender. To prove authorship, use a signature and exchange the
signer's public key too. Combined signing and encryption is not offered in one operation.

## Interpret a signature

- **Signature is good:** the checked bytes match a signature made by the validated key. Compare
  the displayed primary fingerprint with the person you expect. Read any expiry or revocation caveat.
- **Signature does not match:** the checked content does not match this signature. Obtain the
  original file and signature from your correspondent before relying on it.
- **Unable to check the signature:** the app could not establish an answer. It may need the
  correct public key, a supported signature, or a readable file. This is not a successful check.

Changing an input clears its old verdict. For a detached signature, choose the original file and
its separate .sig or .asc file. A result describes the bytes read during that check. Verify again
if the file is changed externally; the app does not watch the file afterwards. Renaming or editing a clear-signed block can change its meaning;
verify the exact message you intend to use.

## Back up and rehearse recovery

On Keys, choose Back up keys. The ZIP includes public keys, available private packets with their
existing protection, and stored revocation certificates. The ZIP itself has no additional password.
Imported keys can be unprotected, and revocation certificates work without a passphrase, so protect
access to the entire archive. Keep an offline copy and keep a recovery certificate separately.

Before treating the backup as reliable, close the app and launch a separate session with
`PGPUTILITY_KEY_STORE` pointing to a new, empty folder. Restore the ZIP there and decrypt a test
message encrypted to your original key. Check the full fingerprint. Close that test session and
remove the override to return to your original store. Do not delete the original store as a test.
The app never needs your real key material in a bug report.

## Manage an existing key

Select a key on Keys and expand Manage this key. Extending expiry keeps the fingerprint and needs
the private primary key and passphrase. Share the updated public key afterwards. A revoked key
cannot be renewed. Changing a passphrase keeps the fingerprint but does not change old backups;
make a new backup and remember that old copies still accept the old passphrase.

Save a revocation certificate while you still have access. Applying one permanently retires that
fingerprint for new encryption and signing. Old messages remain decryptable with the private key.
Send the updated public key to your correspondents. The app does not notify them for you.

Deletion removes local key and recovery files. It does not revoke copies held by others, erase
other backups, or securely wipe storage. Back up first if this is your only working private key.
