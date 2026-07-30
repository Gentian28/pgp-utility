using PgpUtility.Models;

namespace PgpUtility.Services;

public interface IKeyStoreService
{
    IReadOnlyList<PgpKeyInfo> GetAllKeys();
    Task<PgpKeyInfo> ImportPublicKeyAsync(string filePath);
    Task<PgpKeyInfo> ImportPrivateKeyAsync(string filePath);
    Task<PgpKeyInfo> ImportKeyFromStringAsync(string keyData, bool isPrivate);
    Task ExportKeyAsync(string keyId, string outputPath, bool exportPrivate);
    Task DeleteKeyAsync(string keyId);
    string? GetKeyFilePath(string keyId, bool privateKey);
    Task RefreshAsync();
}
