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
    /// Generates a key pair and returns both halves ASCII armored.
    /// </summary>
    /// <remarks>
    /// Copies <see cref="KeyGenerationOptions.Passphrase"/> internally and zeroes its copy, so the
    /// caller is free to clear its own array as soon as this returns.
    /// </remarks>
    Task<(string PublicKey, string PrivateKey)> GenerateKeyPairAsync(
        KeyGenerationOptions options,
        IProgress<string>? progress = null,
        CancellationToken cancellationToken = default);

    PgpKeyInfo ReadPublicKeyInfo(string keySource, bool isFilePath);

    /// <summary>
    /// Reads the metadata of a secret key. No passphrase is required: everything reported here
    /// lives in the public half of the key packet, which is not encrypted.
    /// </summary>
    PgpKeyInfo ReadPrivateKeyInfo(string keySource, bool isFilePath);

    string ExtractPublicKeyFromPrivateKey(string privateKeySource, bool isFilePath);
}
