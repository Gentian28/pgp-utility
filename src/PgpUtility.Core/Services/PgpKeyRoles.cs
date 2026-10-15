using Org.BouncyCastle.Bcpg;
using Org.BouncyCastle.Bcpg.OpenPgp;

namespace PgpUtility.Services;

/// <summary>
/// Picks the right key out of a ring for a given job.
/// </summary>
/// <remarks>
/// A ring is not one key. A conventional OpenPGP key is a master that certifies and signs plus a
/// subkey that encrypts, so "the key" depends on what is being done with it. Getting this wrong
/// does not fail loudly: it fails with "no encryption key found" on a perfectly good key, or by
/// trying to sign with a Curve25519 key that cannot sign.
/// </remarks>
internal static class PgpKeyRoles
{
    /// <summary>
    /// Whether an algorithm can produce signatures at all. ECDH and the encrypt-only RSA and
    /// ElGamal variants cannot, whatever the key flags claim.
    /// </summary>
    internal static bool CanSign(PublicKeyAlgorithmTag algorithm) => algorithm switch
    {
        PublicKeyAlgorithmTag.RsaGeneral or
        PublicKeyAlgorithmTag.RsaSign or
        PublicKeyAlgorithmTag.Dsa or
        PublicKeyAlgorithmTag.ECDsa or
        PublicKeyAlgorithmTag.EdDsa or
        PublicKeyAlgorithmTag.EdDsa_Legacy => true,
        _ => false
    };

    /// <summary>
    /// Unlocks a secret key, translating a bad passphrase into something the user can act on.
    /// </summary>
    /// <remarks>
    /// Shared by decryption, signing and revocation because all three fail the same way and must
    /// report it the same way. Two copies of this would drift, and the one that drifted would
    /// start telling people to retype a passphrase that was already correct.
    /// </remarks>
    internal static PgpPrivateKey ExtractPrivateKey(PgpSecretKey secretKey, char[] passPhrase)
    {
        try
        {
            // GnuPG encodes passphrases as UTF-8, so this is the path that matters for interop
            // and the one this app writes with.
            return secretKey.ExtractPrivateKeyUtf8(passPhrase);
        }
        catch (PgpException utf8Failure) when (IsPassphraseFailure(utf8Failure))
        {
            try
            {
                // BouncyCastle's older default wrote one byte per char. Identical for ASCII,
                // different beyond it, so a key protected that way still opens here.
                return secretKey.ExtractPrivateKey(passPhrase);
            }
            catch (PgpException legacyFailure) when (IsPassphraseFailure(legacyFailure))
            {
                throw new IncorrectPassphraseException(
                    "incorrect passphrase for this key. Check caps lock and your keyboard layout, then try again.",
                    legacyFailure);
            }
        }
    }

    /// <summary>
    /// Distinguishes a bad passphrase from a key this build cannot handle at all. BouncyCastle
    /// reports both as PgpException, and telling a user to retype their passphrase when the real
    /// problem is an unsupported algorithm sends them round in circles.
    /// </summary>
    private static bool IsPassphraseFailure(PgpException ex) =>
        ex.Message.Contains("checksum mismatch", StringComparison.OrdinalIgnoreCase) ||
        ex.Message.Contains("Exception decrypting key", StringComparison.OrdinalIgnoreCase);
}
