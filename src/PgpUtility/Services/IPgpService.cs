using PgpUtility.Models;

namespace PgpUtility.Services;

public interface IPgpService
{
    Task<OperationResult> EncryptFileAsync(
        string inputFilePath,
        string outputFilePath,
        string publicKeySource,
        bool isFilePath,
        bool armor,
        bool withIntegrityCheck,
        IProgress<string>? progress = null,
        CancellationToken cancellationToken = default);

    Task<OperationResult> DecryptFileAsync(
        string inputFilePath,
        string outputFilePath,
        string privateKeySource,
        bool isFilePath,
        string passphrase,
        IProgress<string>? progress = null,
        CancellationToken cancellationToken = default);

    Task<(string PublicKey, string PrivateKey)> GenerateKeyPairAsync(
        KeyGenerationOptions options,
        IProgress<string>? progress = null,
        CancellationToken cancellationToken = default);

    PgpKeyInfo ReadPublicKeyInfo(string keySource, bool isFilePath);
    PgpKeyInfo ReadPrivateKeyInfo(string keySource, bool isFilePath, string? passphrase = null);
    string ExtractPublicKeyFromPrivateKey(string privateKeySource, bool isFilePath);
}
