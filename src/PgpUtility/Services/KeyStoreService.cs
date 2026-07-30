using System.IO;
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

    public KeyStoreService(IPgpService pgpService)
    {
        _pgpService = pgpService;
        _keysDirectory = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
            "PgpUtility", "Keys");
        _indexPath = Path.Combine(_keysDirectory, "index.json");
        Directory.CreateDirectory(_keysDirectory);
        LoadIndex();
    }

    public IReadOnlyList<PgpKeyInfo> GetAllKeys() => _keys.AsReadOnly();

    public async Task<PgpKeyInfo> ImportPublicKeyAsync(string filePath)
    {
        var info = _pgpService.ReadPublicKeyInfo(filePath, true);
        string destFileName = $"pub_{info.KeyId}.asc";
        string destPath = Path.Combine(_keysDirectory, destFileName);
        await Task.Run(() => File.Copy(filePath, destPath, true));

        info.PublicKeyFile = destFileName;
        MergeKey(info);
        await SaveIndexAsync();
        return info;
    }

    public async Task<PgpKeyInfo> ImportPrivateKeyAsync(string filePath)
    {
        var info = _pgpService.ReadPrivateKeyInfo(filePath, true);
        string secFileName = $"sec_{info.KeyId}.asc";
        string secPath = Path.Combine(_keysDirectory, secFileName);
        await Task.Run(() => File.Copy(filePath, secPath, true));

        info.PrivateKeyFile = secFileName;
        info.HasPrivateKey = true;

        // Auto-extract public key from private key
        string pubKeyArmored = _pgpService.ExtractPublicKeyFromPrivateKey(filePath, true);
        string pubFileName = $"pub_{info.KeyId}.asc";
        string pubPath = Path.Combine(_keysDirectory, pubFileName);
        await File.WriteAllTextAsync(pubPath, pubKeyArmored);
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
            string secPath = Path.Combine(_keysDirectory, secFileName);
            await File.WriteAllTextAsync(secPath, keyData);
            info.PrivateKeyFile = secFileName;
            info.HasPrivateKey = true;

            // Auto-extract public key from private key
            string pubKeyArmored = _pgpService.ExtractPublicKeyFromPrivateKey(keyData, false);
            string pubFileName = $"pub_{info.KeyId}.asc";
            string pubPath = Path.Combine(_keysDirectory, pubFileName);
            await File.WriteAllTextAsync(pubPath, pubKeyArmored);
            info.PublicKeyFile = pubFileName;
        }
        else
        {
            info = _pgpService.ReadPublicKeyInfo(keyData, false);
            string pubFileName = $"pub_{info.KeyId}.asc";
            string pubPath = Path.Combine(_keysDirectory, pubFileName);
            await File.WriteAllTextAsync(pubPath, keyData);
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
    }

    private static void TryDeleteFile(string path)
    {
        try { if (File.Exists(path)) File.Delete(path); } catch { }
    }
}
