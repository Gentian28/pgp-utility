namespace PgpUtility.Models;

/// <summary>
/// Public key algorithm for a newly generated key pair.
/// </summary>
public enum PgpKeyAlgorithm
{
    /// <summary>
    /// An Ed25519 signing key with a Curve25519 encryption subkey. Generates in milliseconds,
    /// produces far smaller keys and signatures than RSA, and is understood by GnuPG 2.1 and
    /// later plus every current OpenPGP implementation.
    /// </summary>
    Ed25519,

    /// <summary>
    /// RSA. Slow to generate at 4096 bits and much larger on the wire, but accepted by legacy
    /// tooling that predates elliptic curve support.
    /// </summary>
    Rsa
}

public class KeyGenerationOptions
{
    public string Name { get; set; } = string.Empty;
    public string Email { get; set; } = string.Empty;

    /// <summary>
    /// The passphrase protecting the secret key, held as a char array rather than a string so the
    /// caller can zero it the moment the key is written. This is defence in depth: it shortens the
    /// window in which the passphrase sits in managed memory waiting for a garbage collection that
    /// may never zero the page. It is not protection against an attacker who can already read this
    /// process, and it does not survive being swapped to disk.
    /// </summary>
    public char[] Passphrase { get; set; } = Array.Empty<char>();

    public PgpKeyAlgorithm Algorithm { get; set; } = PgpKeyAlgorithm.Ed25519;

    /// <summary>
    /// RSA modulus size in bits. Ignored for Ed25519, whose size is fixed by the curve.
    /// </summary>
    public int KeySize { get; set; } = 4096;

    public DateTime? ExpirationDate { get; set; }

    public string Identity => string.IsNullOrWhiteSpace(Email)
        ? Name
        : $"{Name} <{Email}>";
}
