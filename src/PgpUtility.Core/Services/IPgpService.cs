using PgpUtility.Models;

namespace PgpUtility.Services;

public interface IPgpService
{
    /// <summary>
    /// Encrypts a file to the given public key. Output is always AES-256 with a modification
    /// detection code; neither is a caller choice.
    /// </summary>
    Task<OperationResult> EncryptFileAsync(
        string inputFilePath,
        string outputFilePath,
        string publicKeySource,
        bool isFilePath,
        bool armor,
        IProgress<string>? progress = null,
        CancellationToken cancellationToken = default);

    /// <summary>
    /// Decrypts a file. The integrity check is verified before the plaintext reaches
    /// <paramref name="outputFilePath"/>; a message that fails it produces no output file.
    /// </summary>
    /// <param name="passphrase">
    /// Not cleared by this method. The caller owns the array and should zero it once done.
    /// </param>
    Task<OperationResult> DecryptFileAsync(
        string inputFilePath,
        string outputFilePath,
        string privateKeySource,
        bool isFilePath,
        char[] passphrase,
        IProgress<string>? progress = null,
        CancellationToken cancellationToken = default);

    /// <summary>
    /// Generates a key pair, ASCII armored, along with a revocation certificate for it.
    /// </summary>
    /// <remarks>
    /// Copies <see cref="KeyGenerationOptions.Passphrase"/> internally and zeroes its copy, so the
    /// caller is free to clear its own array as soon as this returns.
    /// </remarks>
    Task<GeneratedKeyPair> GenerateKeyPairAsync(
        KeyGenerationOptions options,
        IProgress<string>? progress = null,
        CancellationToken cancellationToken = default);

    /// <summary>
    /// Produces a revocation certificate for an existing key, for anyone who generated a key
    /// before this app started emitting one at creation time.
    /// </summary>
    string CreateRevocationCertificate(string privateKeySource, bool isFilePath, char[] passphrase);

    /// <summary>
    /// Encrypts a block of text and returns an armored message in <see cref="OperationResult.Payload"/>.
    /// </summary>
    /// <remarks>
    /// Most real PGP traffic is text in a message or an email rather than a file on disk, so this
    /// is not a convenience wrapper over the file path: it is the common case.
    /// </remarks>
    Task<OperationResult> EncryptTextAsync(
        string text,
        string publicKeySource,
        bool isFilePath,
        CancellationToken cancellationToken = default);

    /// <param name="passphrase">Not cleared by this method. The caller owns the array.</param>
    Task<OperationResult> DecryptTextAsync(
        string armoredText,
        string privateKeySource,
        bool isFilePath,
        char[] passphrase,
        CancellationToken cancellationToken = default);

    PgpKeyInfo ReadPublicKeyInfo(string keySource, bool isFilePath);

    /// <summary>
    /// Reads the metadata of a secret key. No passphrase is required: everything reported here
    /// lives in the public half of the key packet, which is not encrypted.
    /// </summary>
    PgpKeyInfo ReadPrivateKeyInfo(string keySource, bool isFilePath);

    string ExtractPublicKeyFromPrivateKey(string privateKeySource, bool isFilePath);
}
