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
    public void Validate()
    {
        if (string.IsNullOrWhiteSpace(Name) || Identity.Contains('\r') || Identity.Contains('\n'))
            throw new ArgumentException("Enter a name on one line.");
        if (!Enum.IsDefined(Algorithm)) throw new ArgumentException("Choose a supported key algorithm.");
        if (Algorithm == PgpKeyAlgorithm.Rsa && KeySize is not (2048 or 4096))
            throw new ArgumentException("Choose RSA 2048 or 4096 bits.");
        if (ExpirationDate is { } expiry && expiry.ToUniversalTime() <= DateTime.UtcNow.AddSeconds(1))
            throw new ArgumentException("Choose an expiry date in the future.");
        if (Passphrase is null || Passphrase.Length == 0)
            throw new ArgumentException("Enter a passphrase to protect the private key.");
    }

    internal KeyGenerationOptions Snapshot() => new()
    {
        Name = Name, Email = Email, Algorithm = Algorithm, KeySize = KeySize,
        ExpirationDate = ExpirationDate?.ToUniversalTime(), Passphrase = Passphrase
    };
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
