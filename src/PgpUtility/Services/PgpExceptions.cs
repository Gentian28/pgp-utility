namespace PgpUtility.Services;

/// <summary>
/// The supplied passphrase did not unlock the secret key.
/// </summary>
/// <remarks>
/// Distinct from a general PGP failure on purpose. "You typed the wrong passphrase" and "this is
/// not a file I can read" are the two failures a user actually hits, and they act on them
/// differently, so the service has to tell them apart rather than surfacing one opaque message.
/// </remarks>
public class IncorrectPassphraseException : Exception
{
    public IncorrectPassphraseException(string message)
        : base(message) { }

    public IncorrectPassphraseException(string message, Exception innerException)
        : base(message, innerException) { }
}

/// <summary>
/// The ciphertext decrypted, but its modification detection code did not match, so the file was
/// altered after it was encrypted.
/// </summary>
/// <remarks>
/// Treated as a hard failure and the decrypted bytes are discarded. Without an integrity check an
/// OpenPGP message is malleable: an attacker who cannot read the plaintext can still flip chosen
/// bits in it. Producing that output and calling it success would be worse than producing nothing.
/// </remarks>
public class IntegrityCheckFailedException : Exception
{
    public IntegrityCheckFailedException(string message)
        : base(message) { }
}
