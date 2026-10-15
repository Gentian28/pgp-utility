using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.IO.Compression;
using Org.BouncyCastle.Bcpg;
using Org.BouncyCastle.Bcpg.OpenPgp;
using PgpUtility.Models;

namespace PgpUtility.Services;

public class KeyStoreService : IKeyStoreService
{
    private readonly IPgpService _pgpService;
    private readonly KeyLifecycleService _lifecycle = new();
    private readonly string _keysDirectory;
    private readonly string _indexPath;
    private readonly string _lockName;
    private IReadOnlyList<PgpKeyInfo> _keys = [];
    private Dictionary<string, List<string>> _aliases = new(StringComparer.Ordinal);
    private readonly List<string> _warnings = [];
    private static readonly JsonSerializerOptions JsonOptions = new() { WriteIndented = true };

    public KeyStoreService(IPgpService pgpService, string? keysDirectory = null)
    {
        ArgumentNullException.ThrowIfNull(pgpService);
        _pgpService = pgpService;
        _keysDirectory = Path.GetFullPath(keysDirectory ?? KeyStoreLocation.Default());
        _indexPath = Path.Combine(_keysDirectory, "index.json");
        string identity = OperatingSystem.IsWindows() ? _keysDirectory.ToUpperInvariant() : _keysDirectory;
        _lockName = "PgpUtility.Store." + Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(identity)));
        KeyStoreLocation.CreateSecureDirectory(_keysDirectory);
        WithLock(() => { RecoverIndex(); Reload(); SaveIndex(); return true; });
    }

    public string Directory => _keysDirectory;
    public IReadOnlyList<string> Warnings => _warnings.ToArray();
    public IReadOnlyList<PgpKeyInfo> GetAllKeys() => WithLock(() => { Reload(); return _keys; });

    public Task<PgpKeyInfo> ImportPublicKeyAsync(string filePath) =>
        Task.Run(() => WithLock(() => Import(ReadKeyBytes(filePath), isPrivate: false)));

    public Task<PgpKeyInfo> ImportPrivateKeyAsync(string filePath) =>
        Task.Run(() => WithLock(() => Import(ReadKeyBytes(filePath), isPrivate: true)));

    public Task<PgpKeyInfo> ImportKeyFromStringAsync(string keyData, bool isPrivate) =>
        Task.Run(() => WithLock(() => Import(KeyBytes(keyData), isPrivate)));

    public Task<PgpKeyInfo> ImportKeyAsync(string source, bool isFilePath) => Task.Run(() =>
    {
        byte[] bytes = isFilePath ? ReadKeyBytes(source) : KeyBytes(source);
        using var input = new MemoryStream(bytes);
        CryptoInputLimits.CheckKey(input);
        using var decoder = PgpUtilities.GetDecoderStream(input);
        var first = new PgpObjectFactory(decoder).NextPgpObject();
        if (first is not (PgpSecretKeyRing or PgpPublicKeyRing)) throw new PgpException("The input does not contain a public or private key.");
        // Detection finishes before storage is touched. An I/O failure is never retried as
        // a different key type, which would hide the error or silently lose the private half.
        return WithLock(() => Import(bytes, first is PgpSecretKeyRing));
    });

    public Task ExportKeyAsync(string keyId, string outputPath, bool exportPrivate) => Task.Run(() => WithLock(() =>
    {
        Reload();
        var key = Find(keyId) ?? throw new InvalidOperationException("This key is not in the store.");
        string file = exportPrivate ? key.PrivateKeyFile ?? throw new InvalidOperationException("No private key available.") : key.PublicKeyFile;
        FileTransaction.CopyAsync(StorePath(file), outputPath).GetAwaiter().GetResult();
        return true;
    }));

    public Task DeleteKeyAsync(string keyId) => Task.Run(() => WithLock(() =>
    {
        Reload();
        var key = Find(keyId);
        if (key is null) return true;
        var paths = _aliases[key.Fingerprint].Append("rev_" + key.Fingerprint + ".asc")
            .Select(StorePath).Where(File.Exists).Distinct().ToArray();
        var originals = new Dictionary<string, byte[]>();
        try
        {
            // Check all files before deleting any. Keep encrypted original bytes until deletion
            // and index persistence succeed so a later failure can be rolled back.
            foreach (string path in paths)
            {
                if ((File.GetAttributes(path) & FileAttributes.ReadOnly) != 0)
                    throw new IOException("A key file is read-only. The key has not been deleted.");
                using var check = new FileStream(path, FileMode.Open, FileAccess.ReadWrite, FileShare.None);
                using var copy = new MemoryStream();
                check.CopyTo(copy);
                originals.Add(path, copy.ToArray());
            }
            foreach (string path in paths) File.Delete(path);
            Reload();
            SaveIndex();
            return true;
        }
        catch
        {
            foreach (var original in originals.Where(p => !File.Exists(p.Key)))
            {
                using var restore = new FileTransaction(original.Key);
                restore.Stream.Write(original.Value);
                restore.Commit();
            }
            Reload();
            throw;
        }
        finally { foreach (var bytes in originals.Values) Array.Clear(bytes); }
    }));

    public string? GetKeyFilePath(string keyId, bool privateKey) => WithLock(() =>
    {
        Reload();
        var key = Find(keyId);
        if (key is null) return null;
        string? name = privateKey ? key.PrivateKeyFile : key.PublicKeyFile;
        return name is null ? null : StorePath(name);
    });

    public Task RefreshAsync() => Task.Run(() => WithLock(() => { Reload(); SaveIndex(); return true; }));

    public Task SaveRevocationCertificateAsync(string keyId, string certificate) => Task.Run(() => WithLock(() =>
    {
        Reload();
        var key = Find(keyId) ?? throw new InvalidOperationException("The selected key is no longer in the store.");
        _ = _lifecycle.ApplyRevocation(File.ReadAllText(StorePath(key.PublicKeyFile)), certificate);
        Write("rev_" + key.Fingerprint + ".asc", certificate);
        return true;
    }));

    public async Task ExportRevocationCertificateAsync(string keyId, string outputPath, char[] passphrase)
    {
        char[] owned = (char[])passphrase.Clone();
        try
        {
            await Task.Run(() => WithLock(() =>
            {
                Reload();
                var key = Find(keyId) ?? throw new InvalidOperationException("The selected key is no longer in the store.");
                string name = "rev_" + key.Fingerprint + ".asc";
                string certificate;
                if (File.Exists(StorePath(name))) certificate = File.ReadAllText(StorePath(name));
                else
                {
                    if (key.PrivateKeyFile is null) throw new InvalidOperationException("Generating a certificate needs the private key and its passphrase.");
                    certificate = _pgpService.CreateRevocationCertificate(StorePath(key.PrivateKeyFile), true, owned);
                    Write(name, certificate);
                }
                FileTransaction.WriteTextAsync(outputPath, certificate).GetAwaiter().GetResult();
                return true;
            }));
        }
        finally { Array.Clear(owned); }
    }

    public Task ApplyRevocationAsync(string keyId, string certificate) => Task.Run(() => WithLock(() =>
    {
        Reload();
        var key = Find(keyId) ?? throw new InvalidOperationException("The selected key is no longer in the store.");
        string revoked = _lifecycle.ApplyRevocation(File.ReadAllText(StorePath(key.PublicKeyFile)), certificate);
        Import(Encoding.UTF8.GetBytes(revoked), false);
        Write("rev_" + key.Fingerprint + ".asc", certificate);
        return true;
    }));

    public async Task ExtendExpiryAsync(string keyId, DateTime expiry, char[] passphrase)
    {
        char[] owned = (char[])passphrase.Clone();
        try
        {
            await Task.Run(() => WithLock(() =>
            {
                Reload();
                var key = Find(keyId) ?? throw new InvalidOperationException("The selected key is no longer in the store.");
                if (key.PrivateKeyFile is null) throw new InvalidOperationException("Renewal needs the private primary key.");
                string changed = _lifecycle.ExtendExpiryAsync(File.ReadAllText(StorePath(key.PrivateKeyFile)), owned, expiry).GetAwaiter().GetResult();
                Import(Encoding.UTF8.GetBytes(changed), true);
                return true;
            }));
        }
        finally { Array.Clear(owned); }
    }

    public async Task ChangePassphraseAsync(string keyId, char[] oldPassphrase, char[] newPassphrase)
    {
        char[] oldOwned = (char[])oldPassphrase.Clone();
        char[] newOwned = (char[])newPassphrase.Clone();
        try
        {
            await Task.Run(() => WithLock(() =>
            {
                Reload();
                var key = Find(keyId) ?? throw new InvalidOperationException("The selected key is no longer in the store.");
                if (key.PrivateKeyFile is null) throw new InvalidOperationException("No private key is available.");
                string changed = _lifecycle.ChangePassphraseAsync(File.ReadAllText(StorePath(key.PrivateKeyFile)), oldOwned, newOwned).GetAwaiter().GetResult();
                Import(Encoding.UTF8.GetBytes(changed), true);
                return true;
            }));
        }
        finally { Array.Clear(oldOwned); Array.Clear(newOwned); }
    }

    public Task ExportBackupAsync(string outputPath) => Task.Run(() => WithLock(() =>
    {
        Reload();
        if (_keys.Count == 0) throw new InvalidOperationException("There are no keys to back up.");
        using var transaction = new FileTransaction(outputPath);
        using (var archive = new ZipArchive(transaction.Stream, ZipArchiveMode.Create, leaveOpen: true))
        {
            var manifest = archive.CreateEntry("manifest.json");
            using (var writer = new StreamWriter(manifest.Open(), new UTF8Encoding(false)))
                writer.Write(JsonSerializer.Serialize(new BackupManifest(1, DateTime.UtcNow, _keys.Select(k => k.Fingerprint).ToArray()), JsonOptions));
            foreach (var key in _keys)
            {
                foreach (string name in new[] { key.PublicKeyFile, key.PrivateKeyFile, "rev_" + key.Fingerprint + ".asc" }.OfType<string>())
                {
                    string sourcePath = StorePath(name);
                    if (!File.Exists(sourcePath)) continue;
                    string prefix = name.StartsWith("sec_", StringComparison.Ordinal) ? "sec_" : name.StartsWith("rev_", StringComparison.Ordinal) ? "rev_" : "pub_";
                    using var target = archive.CreateEntry(prefix + key.Fingerprint + ".asc").Open();
                    using var source = File.OpenRead(sourcePath);
                    source.CopyTo(target);
                }
            }
        }
        transaction.Commit();
        return true;
    }));

    public Task<int> RestoreBackupAsync(string inputPath) => Task.Run(() => WithLock(() =>
    {
        const int maxEntrySize = 16 * 1024 * 1024;
        const long maxBackupSize = 64 * 1024 * 1024;
        using var archive = ZipFile.OpenRead(inputPath);
        if (archive.Entries.Count > 4096 || archive.Entries.Sum(e => e.Length) > maxBackupSize)
            throw new InvalidDataException("This backup is too large to restore safely.");
        var entries = new Dictionary<string, byte[]>(StringComparer.OrdinalIgnoreCase);
        long total = 0;
        try
        {
            foreach (var entry in archive.Entries)
            {
                string name = entry.FullName;
                if (Path.GetFileName(name) != name || name.Contains('/') || name.Contains('\\') || entry.Length > maxEntrySize)
                    throw new InvalidDataException("The backup contains an unsupported filename or oversized entry.");
                using var source = entry.Open();
                using var buffer = new MemoryStream();
                byte[] block = new byte[65536];
                try
                {
                    int count;
                    while ((count = source.Read(block)) > 0)
                    {
                        total += count;
                        if (buffer.Length + count > maxEntrySize || total > maxBackupSize)
                            throw new InvalidDataException("The backup expands beyond the safe restore limit.");
                        buffer.Write(block, 0, count);
                    }
                }
                finally { Array.Clear(block); }
                if (!entries.TryAdd(name, buffer.ToArray())) throw new InvalidDataException("The backup contains duplicate filenames.");
            }
            if (!entries.TryGetValue("manifest.json", out var metadata)) throw new InvalidDataException("This is not a PGP Utility backup.");
            var manifest = JsonSerializer.Deserialize<BackupManifest>(metadata);
            if (manifest?.Format != 1 || manifest.Fingerprints is null || manifest.Fingerprints.Length == 0 ||
                manifest.Fingerprints.Distinct(StringComparer.Ordinal).Count() != manifest.Fingerprints.Length ||
                manifest.Fingerprints.Any(fp => fp is null || fp.Length is not (40 or 64) || fp.Any(c => !char.IsAsciiHexDigit(c))))
                throw new InvalidDataException("The backup manifest is invalid or unsupported.");
            var publicKeys = new Dictionary<string, string>(StringComparer.Ordinal);
            foreach (var entry in entries.Where(e => e.Key != "manifest.json" && !e.Key.StartsWith("rev_", StringComparison.Ordinal)))
            {
                bool secret = entry.Key.StartsWith("sec_", StringComparison.Ordinal);
                if (!secret && !entry.Key.StartsWith("pub_", StringComparison.Ordinal)) throw new InvalidDataException("Unsupported backup entry.");
                using var source = new MemoryStream(entry.Value);
                var ring = secret ? PgpKeyValidation.PublicRing(PgpKeyValidation.ReadSecret(source)) : PgpKeyValidation.ReadPublic(source);
                var identity = new PgpKeyValidation(ring);
                if (entry.Key != (secret ? "sec_" : "pub_") + identity.Fingerprint + ".asc" || !manifest.Fingerprints.Contains(identity.Fingerprint, StringComparer.Ordinal))
                    throw new InvalidDataException("A backup key does not match its manifest fingerprint.");
                publicKeys[identity.Fingerprint] = Armor(ring.Encode);
            }
            if (manifest.Fingerprints.Any(fp => !publicKeys.ContainsKey(fp))) throw new InvalidDataException("The backup is incomplete.");
            foreach (var entry in entries.Where(e => e.Key.StartsWith("rev_", StringComparison.Ordinal)))
            {
                string fingerprint = Path.GetFileNameWithoutExtension(entry.Key)[4..];
                if (!publicKeys.TryGetValue(fingerprint, out string? publicKey)) throw new InvalidDataException("A revocation certificate has no matching key.");
                _ = _lifecycle.ApplyRevocation(publicKey, Encoding.UTF8.GetString(entry.Value));
            }
            // Every entry is validated before modifying the store. Retain a rollback snapshot
            // until all imports complete, including their index updates.
            Reload();
            var original = System.IO.Directory.EnumerateFiles(_keysDirectory, "*.asc")
                .ToDictionary(path => Path.GetFileName(path)!, File.ReadAllBytes, StringComparer.Ordinal);
            try
            {
                foreach (var entry in entries.Where(e => e.Key.StartsWith("pub_", StringComparison.Ordinal))) Import(entry.Value, false);
                foreach (var entry in entries.Where(e => e.Key.StartsWith("sec_", StringComparison.Ordinal))) Import(entry.Value, true);
                foreach (var entry in entries.Where(e => e.Key.StartsWith("rev_", StringComparison.Ordinal))) Write(entry.Key, Encoding.UTF8.GetString(entry.Value));
                return manifest.Fingerprints.Length;
            }
            catch
            {
                foreach (string path in System.IO.Directory.EnumerateFiles(_keysDirectory, "*.asc"))
                    if (!original.ContainsKey(Path.GetFileName(path))) File.Delete(path);
                foreach (var entry in original)
                {
                    using var restore = new FileTransaction(StorePath(entry.Key!));
                    restore.Stream.Write(entry.Value);
                    restore.Commit(replaceExisting: true);
                }
                Reload(); SaveIndex();
                throw;
            }
            finally { foreach (var bytes in original.Values) Array.Clear(bytes); }
        }
        finally { foreach (var bytes in entries.Values) Array.Clear(bytes); }
    }));

    private static byte[] ReadKeyBytes(string path)
    {
        using var input = File.OpenRead(path);
        CryptoInputLimits.CheckKey(input);
        using var output = new MemoryStream();
        byte[] buffer = new byte[65536];
        int count;
        while ((count = input.Read(buffer)) > 0)
        {
            if (output.Length + count > CryptoInputLimits.TextBytes) throw new PgpException("This key file exceeds the supported 16 MiB limit.");
            output.Write(buffer, 0, count);
        }
        return output.ToArray();
    }

    private static byte[] KeyBytes(string text)
    {
        CryptoInputLimits.CheckText(text);
        return Encoding.UTF8.GetBytes(text);
    }

    private sealed record BackupManifest(int Format, DateTime CreatedUtc, string[] Fingerprints);

    private PgpKeyInfo Import(byte[] bytes, bool isPrivate)
    {
        using var source = new MemoryStream(bytes);
        PgpSecretKeyRing? secret = isPrivate ? PgpKeyValidation.ReadSecret(source) : null;
        var ring = secret is null ? PgpKeyValidation.ReadPublic(source) : PgpKeyValidation.PublicRing(secret);
        var validated = new PgpKeyValidation(ring);
        Reload();
        var existing = _keys.SingleOrDefault(k => k.Fingerprint == validated.Fingerprint);
        if (existing is not null)
        {
            using var oldPublic = File.OpenRead(StorePath(existing.PublicKeyFile));
            ring = PgpPublicKeyRing.Join(PgpKeyValidation.ReadPublic(oldPublic), ring);
            if (existing.PrivateKeyFile is not null)
            {
                using var oldPrivate = File.OpenRead(StorePath(existing.PrivateKeyFile));
                var oldSecret = PgpKeyValidation.ReadSecret(oldPrivate);
                if (secret is null) secret = oldSecret;
                else foreach (var oldKey in oldSecret.GetSecretKeys())
                    if (secret.GetSecretKey(oldKey.GetFingerprint()) is not { } incoming ||
                        (incoming.IsPrivateKeyEmpty && !oldKey.IsPrivateKeyEmpty))
                        secret = PgpSecretKeyRing.InsertSecretKey(secret, oldKey);
            }
        }
        validated = new PgpKeyValidation(ring);
        string publicName = "pub_" + validated.Fingerprint + ".asc";
        string privateName = "sec_" + validated.Fingerprint + ".asc";
        var affected = (_aliases.TryGetValue(validated.Fingerprint, out var known) ? known : [])
            .Concat(new[] { publicName, privateName, "index.json", "index.json.bak" }).Distinct(StringComparer.Ordinal).ToArray();
        return RollBackOnFailure(affected, () =>
        {
            // Public updates must also reach secret rings so an imported revocation takes effect
            // when signing. The secret-key packet's existing passphrase protection is retained.
            if (secret is not null)
            {
                secret = PgpSecretKeyRing.ReplacePublicKeys(secret, ring);
                Write(privateName, Armor(secret.Encode));
            }
            Write(publicName, Armor(ring.Encode));
            // Canonical files are durable before legacy aliases are removed. A process interruption
            // leaves both recoverable, and Reload merges their certification information.
            if (_aliases.TryGetValue(validated.Fingerprint, out var aliases))
                foreach (string legacy in aliases)
                    if (legacy != publicName && legacy != privateName) File.Delete(StorePath(legacy));
            Reload();
            SaveIndex();
            return _keys.Single(k => k.Fingerprint == validated.Fingerprint);
        });
    }

    private T RollBackOnFailure<T>(IReadOnlyList<string> names, Func<T> update)
    {
        var originals = names.ToDictionary(name => name,
            name => File.Exists(StorePath(name)) ? File.ReadAllBytes(StorePath(name)) : null, StringComparer.Ordinal);
        try { return update(); }
        catch (Exception failure)
        {
            var recoveryErrors = new List<Exception>();
            foreach (var original in originals)
            {
                try
                {
                    string path = StorePath(original.Key);
                    if (original.Value is null)
                    {
                        if (File.Exists(path)) File.Delete(path);
                    }
                    else if (!File.Exists(path) || !File.ReadAllBytes(path).AsSpan().SequenceEqual(original.Value))
                    {
                        using var transaction = new FileTransaction(path);
                        transaction.Stream.Write(original.Value);
                        transaction.Commit(replaceExisting: true);
                    }
                }
                catch (Exception recovery) when (recovery is IOException or UnauthorizedAccessException)
                { recoveryErrors.Add(recovery); }
            }
            if (recoveryErrors.Count > 0)
                throw new AggregateException("The key update failed and rollback also failed. Check the store and your tested backup before continuing.", new[] { failure }.Concat(recoveryErrors));
            Reload();
            throw;
        }
        finally { foreach (var bytes in originals.Values.OfType<byte[]>()) Array.Clear(bytes); }
    }

    private void Reload()
    {
        var rings = new Dictionary<string, PgpPublicKeyRing>(StringComparer.Ordinal);
        var publicPaths = new Dictionary<string, string>(StringComparer.Ordinal);
        var privatePaths = new Dictionary<string, string>(StringComparer.Ordinal);
        var aliases = new Dictionary<string, List<string>>(StringComparer.Ordinal);
        foreach (string path in System.IO.Directory.EnumerateFiles(_keysDirectory, "*.asc")
            .Where(p => Path.GetFileName(p).StartsWith("pub_", StringComparison.Ordinal) || Path.GetFileName(p).StartsWith("sec_", StringComparison.Ordinal))
            .OrderBy(p => p, StringComparer.Ordinal))
        {
            try
            {
                using var source = File.OpenRead(path);
                bool isPrivate = Path.GetFileName(path).StartsWith("sec_", StringComparison.Ordinal);
                var secret = isPrivate ? PgpKeyValidation.ReadSecret(source) : null;
                var ring = secret is null ? PgpKeyValidation.ReadPublic(source) : PgpKeyValidation.PublicRing(secret);
                string fingerprint = new PgpKeyValidation(ring).Fingerprint;
                if (rings.TryGetValue(fingerprint, out var previous)) ring = PgpPublicKeyRing.Join(previous, ring);
                rings[fingerprint] = ring;
                if (!aliases.TryGetValue(fingerprint, out var files)) aliases[fingerprint] = files = [];
                files.Add(Path.GetFileName(path));
                string name = Path.GetFileName(path);
                if (secret is not null && secret.GetSecretKeys().Any(k => !k.IsPrivateKeyEmpty))
                {
                    if (!privatePaths.ContainsKey(fingerprint) || name == "sec_" + fingerprint + ".asc") privatePaths[fingerprint] = name;
                }
                else if (!isPrivate && (!publicPaths.ContainsKey(fingerprint) || name == "pub_" + fingerprint + ".asc")) publicPaths[fingerprint] = name;
            }
            catch (Exception ex) when (ex is PgpException or IOException or ArgumentException or InvalidOperationException or InvalidCastException or IndexOutOfRangeException or UnauthorizedAccessException)
            {
                Warn($"A key file could not be loaded: {Path.GetFileName(path)}. The original has been preserved. {ex.Message}");
            }
        }
        var keys = new List<PgpKeyInfo>();
        foreach (var entry in rings)
        {
            if (!publicPaths.TryGetValue(entry.Key, out string? publicName))
            {
                publicName = "pub_" + entry.Key + ".asc";
                Write(publicName, Armor(entry.Value.Encode));
                aliases[entry.Key].Add(publicName);
            }
            // Persist the union so a stale duplicate cannot hide a known revocation.
            string publicText = Armor(entry.Value.Encode);
            if (File.ReadAllText(StorePath(publicName)) != publicText) Write(publicName, publicText);
            privatePaths.TryGetValue(entry.Key, out string? privateName);
            PgpSecretKeyRing? privateRing = null;
            if (privateName is not null)
            {
                PgpSecretKeyRing secret;
                using (var input = File.OpenRead(StorePath(privateName))) secret = PgpKeyValidation.ReadSecret(input);
                var merged = PgpSecretKeyRing.ReplacePublicKeys(secret, entry.Value);
                privateRing = merged;
                string armored = Armor(merged.Encode);
                if (File.ReadAllText(StorePath(privateName)) != armored) Write(privateName, armored);
            }
            var key = new PgpKeyValidation(entry.Value).Describe(privateName is not null, privateRing);
            key.PublicKeyFile = publicName;
            key.PrivateKeyFile = privateName;
            keys.Add(key);
        }
        _aliases = aliases;
        _keys = keys.AsReadOnly();
    }

    private PgpKeyInfo? Find(string id)
    {
        var matches = _keys.Where(k => k.Fingerprint == id || k.KeyId == id).ToArray();
        if (matches.Length > 1) throw new InvalidOperationException("That key ID is ambiguous. Select the full fingerprint.");
        return matches.SingleOrDefault();
    }

    private void RecoverIndex()
    {
        if (!File.Exists(_indexPath)) return;
        try { _ = JsonSerializer.Deserialize<List<PgpKeyInfo>>(File.ReadAllText(_indexPath), JsonOptions); }
        catch (JsonException)
        {
            File.Move(_indexPath, StorePath("index.corrupt." + Guid.NewGuid().ToString("N") + ".json"));
            Warn("The key index was damaged and has been rebuilt from the key files. The damaged index was preserved in the key folder.");
        }
    }

    private void SaveIndex()
    {
        if (File.Exists(_indexPath)) FileTransaction.CopyAsync(_indexPath, _indexPath + ".bak", replaceExisting: true).GetAwaiter().GetResult();
        FileTransaction.WriteTextAsync(_indexPath, JsonSerializer.Serialize(_keys, JsonOptions), replaceExisting: true).GetAwaiter().GetResult();
    }

    private void Write(string name, string text) => FileTransaction.WriteTextAsync(StorePath(name), text, replaceExisting: true).GetAwaiter().GetResult();

    private string StorePath(string name)
    {
        if (string.IsNullOrEmpty(name) || Path.GetFileName(name) != name || name.Contains('/') || name.Contains('\\'))
            throw new IOException("Invalid key-store filename.");
        return Path.Combine(_keysDirectory, name);
    }

    private void Warn(string message) { if (!_warnings.Contains(message)) _warnings.Add(message); }

    private T WithLock<T>(Func<T> action)
    {
        using var mutex = new Mutex(false, _lockName);
        bool acquired;
        try { acquired = mutex.WaitOne(TimeSpan.FromSeconds(15)); }
        catch (AbandonedMutexException) { acquired = true; }
        if (!acquired) throw new IOException("The key store is busy in another app instance. Try again after its operation completes.");
        try { return action(); }
        finally { mutex.ReleaseMutex(); }
    }

    internal static string Armor(Action<Stream> encode)
    {
        using var buffer = new MemoryStream();
        using (var armor = new ArmoredOutputStream(buffer)) encode(armor);
        return Encoding.UTF8.GetString(buffer.ToArray());
    }
}
