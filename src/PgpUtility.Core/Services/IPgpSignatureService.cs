using PgpUtility.Models;

namespace PgpUtility.Services;

/// <summary>
/// Detached signatures: proving who produced a file, as opposed to hiding what is in it.
/// </summary>
/// <remarks>
/// Detached rather than inline on purpose. The original file is left exactly as it was and the
/// signature travels beside it, so a recipient without this tool can still open the file, and a
/// signature can be added to something already published without reissuing it.
///
/// A separate interface from IPgpService because signing answers a different question from
/// encryption. Encrypting to someone says nothing about who sent it, and the two are routinely
/// confused: an encrypted file with no signature carries no evidence of authorship at all.
/// </remarks>
public interface IPgpSignatureService
{
    /// <param name="passphrase">Not cleared by this method. The caller owns the array.</param>
    Task<OperationResult> SignFileAsync(
        string inputFilePath,
        string signatureFilePath,
        string privateKeySource,
        bool isFilePath,
        char[] passphrase,
        bool armor,
        IProgress<string>? progress = null,
        CancellationToken cancellationToken = default);

    Task<SignatureVerification> VerifyFileAsync(
        string inputFilePath,
        string signatureFilePath,
        string publicKeySource,
        bool isFilePath,
        IProgress<string>? progress = null,
        CancellationToken cancellationToken = default);

    /// <summary>Signs text and returns a clear-signed message, the form used in email.</summary>
    Task<OperationResult> SignTextAsync(
        string text,
        string privateKeySource,
        bool isFilePath,
        char[] passphrase,
        CancellationToken cancellationToken = default);

    /// <summary>Verifies a clear-signed message and reports what it says about the signer.</summary>
    Task<SignatureVerification> VerifyTextAsync(
        string clearSignedText,
        string publicKeySource,
        bool isFilePath,
        CancellationToken cancellationToken = default);
}
