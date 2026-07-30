namespace PgpUtility.Models;

/// <summary>
/// The outcome of checking a detached signature.
/// </summary>
/// <remarks>
/// <see cref="IsValid"/> is deliberately separate from <see cref="Completed"/>. "The signature
/// does not match" and "something went wrong before we could check" are different answers, and
/// collapsing them into one boolean is how a verification failure ends up reported as a valid
/// signature or the reverse.
/// </remarks>
public sealed class SignatureVerification
{
    /// <summary>True when the check ran to completion, whatever its verdict.</summary>
    public bool Completed { get; init; }

    /// <summary>True only when the signature is cryptographically good for this exact file.</summary>
    public bool IsValid { get; init; }

    public string Message { get; init; } = string.Empty;

    public string? SignerKeyId { get; init; }

    public string? SignerUserId { get; init; }

    public DateTime? SignedAt { get; init; }

    /// <summary>
    /// Set when the signature verifies but the signing key should not be trusted at face value,
    /// because it is revoked or expired. A good signature from a revoked key is still a fact
    /// about the bytes, so this is a caveat rather than a failure.
    /// </summary>
    public string? Caveat { get; init; }

    public static SignatureVerification Valid(
        string message, string keyId, string? userId, DateTime signedAt, string? caveat = null) =>
        new()
        {
            Completed = true,
            IsValid = true,
            Message = message,
            SignerKeyId = keyId,
            SignerUserId = userId,
            SignedAt = signedAt,
            Caveat = caveat
        };

    public static SignatureVerification Invalid(string message, string? keyId = null) =>
        new() { Completed = true, IsValid = false, Message = message, SignerKeyId = keyId };

    /// <summary>The check could not be performed at all.</summary>
    public static SignatureVerification Failed(string message) =>
        new() { Completed = false, IsValid = false, Message = message };
}
