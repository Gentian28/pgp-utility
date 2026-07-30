namespace PgpUtility.Models;

/// <summary>
/// Everything key generation produces, all ASCII armored.
/// </summary>
/// <param name="PublicKey">Share freely. This is what others encrypt to.</param>
/// <param name="PrivateKey">Never share. Protected by the passphrase, and only by it.</param>
/// <param name="RevocationCertificate">
/// A pre-signed statement that this key is no longer to be used.
/// </param>
/// <remarks>
/// The revocation certificate is generated here, at creation, because generating one later needs
/// the private key and the passphrase. If either is lost, which is the main reason to revoke,
/// it is already too late to make one. Publishing it retires the key; anyone who holds it can
/// retire the key, so it wants storing separately from the key itself.
/// </remarks>
public sealed record GeneratedKeyPair(
    string PublicKey,
    string PrivateKey,
    string RevocationCertificate);
