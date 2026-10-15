using PgpUtility.Models;

namespace PgpUtility.Services;

public interface IKeyStoreService
{
    IReadOnlyList<PgpKeyInfo> GetAllKeys();
    Task<PgpKeyInfo> ImportPublicKeyAsync(string filePath);
    Task<PgpKeyInfo> ImportPrivateKeyAsync(string filePath);
    Task<PgpKeyInfo> ImportKeyFromStringAsync(string keyData, bool isPrivate);
    Task<PgpKeyInfo> ImportKeyAsync(string source, bool isFilePath);
    Task ExportKeyAsync(string keyId, string outputPath, bool exportPrivate);
    Task DeleteKeyAsync(string keyId);
    string? GetKeyFilePath(string keyId, bool privateKey);
    Task RefreshAsync();
    IReadOnlyList<string> Warnings { get; }
    Task SaveRevocationCertificateAsync(string keyId, string certificate);
    Task ExportRevocationCertificateAsync(string keyId, string outputPath, char[] passphrase);
    Task ApplyRevocationAsync(string keyId, string certificate);
    Task ExtendExpiryAsync(string keyId, DateTime expiry, char[] passphrase);
    Task ChangePassphraseAsync(string keyId, char[] oldPassphrase, char[] newPassphrase);
    Task ExportBackupAsync(string outputPath);
    Task<int> RestoreBackupAsync(string inputPath);
}
