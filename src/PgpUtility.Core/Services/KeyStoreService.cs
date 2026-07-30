using System.Text.Json;
using PgpUtility.Models;

namespace PgpUtility.Services;

public class KeyStoreService : IKeyStoreService
{
    private readonly string _keysDirectory;
    private readonly string _indexPath;
    private readonly IPgpService _pgpService;
    private List<PgpKeyInfo> _keys = new();

    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        WriteIndented = true
    };

    /// <param name="keysDirectory">
    /// Where the store lives. Defaults to <see cref="KeyStoreLocation.Default"/>. Overridden by
    /// tests so a run never touches the developer's real key store, which is the sort of thing
    /// that is only noticed after it has already happened.
    /// </param>
    public KeyStoreService(IPgpService pgpService, string? keysDirectory = null)
    {
        _pgpService = pgpService;
        _keysDirectory = keysDirectory ?? KeyStoreLocation.Default();
        _indexPath = Path.Combine(_keysDirectory, "index.json");
        KeyStoreLocation.CreateSecureDirectory(_keysDirectory);
        LoadIndex();
    }

    /// <summary>The directory this store reads and writes. Exposed so the UI can offer to open it.</summary>
    public string Directory => _keysDirectory;

    public IReadOnlyList<PgpKeyInfo> GetAllKeys() => _keys.AsReadOnly();

    public async Task<PgpKeyInfo> ImportPublicKeyAsync(string filePath)
    {
        var info = _pgpService.ReadPublicKeyInfo(filePath, true);
        string destFileName = $"pub_{info.KeyId}.asc";
        await CopyIntoStoreAsync(filePath, destFileName);

        info.PublicKeyFile = destFileName;
        MergeKey(info);
        await SaveIndexAsync();
        return info;
    }

    public async Task<PgpKeyInfo> ImportPrivateKeyAsync(string filePath)
    {
        var info = _pgpService.ReadPrivateKeyInfo(filePath, true);
        string secFileName = $"sec_{info.KeyId}.asc";
        await CopyIntoStoreAsync(filePath, secFileName);

        info.PrivateKeyFile = secFileName;
        info.HasPrivateKey = true;

        // Auto-extract public key from private key
        string pubKeyArmored = _pgpService.ExtractPublicKeyFromPrivateKey(filePath, true);
        string pubFileName = $"pub_{info.KeyId}.asc";
        await WriteIntoStoreAsync(pubFileName, pubKeyArmored);
        info.PublicKeyFile = pubFileName;

        MergeKey(info);
        await SaveIndexAsync();
        return info;
    }

    public async Task<PgpKeyInfo> ImportKeyFromStringAsync(string keyData, bool isPrivate)
    {
        PgpKeyInfo info;
        if (isPrivate)
        {
            info = _pgpService.ReadPrivateKeyInfo(keyData, false);
            string secFileName = $"sec_{info.KeyId}.asc";
            await WriteIntoStoreAsync(secFileName, keyData);
            info.PrivateKeyFile = secFileName;
            info.HasPrivateKey = true;

            // Auto-extract public key from private key
            string pubKeyArmored = _pgpService.ExtractPublicKeyFromPrivateKey(keyData, false);
            string pubFileName = $"pub_{info.KeyId}.asc";
            await WriteIntoStoreAsync(pubFileName, pubKeyArmored);
            info.PublicKeyFile = pubFileName;
        }
        else
        {
            info = _pgpService.ReadPublicKeyInfo(keyData, false);
            string pubFileName = $"pub_{info.KeyId}.asc";
            await WriteIntoStoreAsync(pubFileName, keyData);
            info.PublicKeyFile = pubFileName;
        }

        MergeKey(info);
        await SaveIndexAsync();
        return info;
    }

    public async Task ExportKeyAsync(string keyId, string outputPath, bool exportPrivate)
    {
        var key = _keys.FirstOrDefault(k => k.KeyId == keyId)
            ?? throw new InvalidOperationException($"Key {keyId} not found.");

        string sourceFile = exportPrivate
            ? key.PrivateKeyFile ?? throw new InvalidOperationException("No private key available.")
            : key.PublicKeyFile;

        string sourcePath = Path.Combine(_keysDirectory, sourceFile);
        await Task.Run(() => File.Copy(sourcePath, outputPath, true));

        // An exported private key lands wherever the user chose, outside the store's protected
        // directory, so it needs its own mode set rather than inheriting a permissive one.
        if (exportPrivate)
            KeyStoreLocation.RestrictFile(outputPath);
    }

    public async Task DeleteKeyAsync(string keyId)
    {
        var key = _keys.FirstOrDefault(k => k.KeyId == keyId);
        if (key == null) return;

        await Task.Run(() =>
        {
            TryDeleteFile(Path.Combine(_keysDirectory, key.PublicKeyFile));
            if (key.PrivateKeyFile != null)
                TryDeleteFile(Path.Combine(_keysDirectory, key.PrivateKeyFile));
        });

        _keys.Remove(key);
        await SaveIndexAsync();
    }

    public string? GetKeyFilePath(string keyId, bool privateKey)
    {
        var key = _keys.FirstOrDefault(k => k.KeyId == keyId);
        if (key == null) return null;

        string fileName = privateKey
            ? key.PrivateKeyFile ?? key.PublicKeyFile
            : key.PublicKeyFile;

        string fullPath = Path.Combine(_keysDirectory, fileName);
        return File.Exists(fullPath) ? fullPath : null;
    }

    public async Task RefreshAsync()
    {
        await Task.Run(LoadIndex);
    }

    // --- Writing ---

    // Every path that puts a file in the store goes through one of these two, so there is a
    // single place where the file mode is applied. A key written by a route that forgot to
    // restrict it would be world readable on Unix and show no symptom on Windows.

    private async Task WriteIntoStoreAsync(string fileName, string contents)
    {
        string path = Path.Combine(_keysDirectory, fileName);
        await File.WriteAllTextAsync(path, contents);
        KeyStoreLocation.RestrictFile(path);
    }

    private async Task CopyIntoStoreAsync(string sourcePath, string fileName)
    {
        string path = Path.Combine(_keysDirectory, fileName);
        await Task.Run(() => File.Copy(sourcePath, path, true));
        // A copy carries the source file's permissions, so this cannot be left to the directory.
        KeyStoreLocation.RestrictFile(path);
    }

    private void MergeKey(PgpKeyInfo newInfo)
    {
        var existing = _keys.FirstOrDefault(k => k.KeyId == newInfo.KeyId);
        if (existing != null)
        {
            existing.UserId = newInfo.UserId;
            existing.Fingerprint = newInfo.Fingerprint;
            existing.Algorithm = newInfo.Algorithm;
            existing.KeySize = newInfo.KeySize;
            existing.CreationDate = newInfo.CreationDate;
            existing.ExpirationDate = newInfo.ExpirationDate;
            if (!string.IsNullOrEmpty(newInfo.PublicKeyFile))
                existing.PublicKeyFile = newInfo.PublicKeyFile;
            if (newInfo.PrivateKeyFile != null)
            {
                existing.PrivateKeyFile = newInfo.PrivateKeyFile;
                existing.HasPrivateKey = true;
            }
        }
        else
        {
            _keys.Add(newInfo);
        }
    }

    private void LoadIndex()
    {
        if (File.Exists(_indexPath))
        {
            string json = File.ReadAllText(_indexPath);
            _keys = JsonSerializer.Deserialize<List<PgpKeyInfo>>(json, JsonOptions) ?? new();
        }
        else
        {
            _keys = new();
        }
    }

    private async Task SaveIndexAsync()
    {
        string json = JsonSerializer.Serialize(_keys, JsonOptions);
        await File.WriteAllTextAsync(_indexPath, json);
        // The index lists who a user corresponds with. Not secret key material, but not something
        // to leave readable to every account on a shared machine either.
        KeyStoreLocation.RestrictFile(_indexPath);
    }

    private static void TryDeleteFile(string path)
    {
        try { if (File.Exists(path)) File.Delete(path); } catch { }
    }
}
