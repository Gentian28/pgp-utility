using System.Text.Json;
using PgpUtility.Models;
using PgpUtility.Services;

if (args.Length != 2 || args[0] is not ("seed" or "verify"))
    throw new ArgumentException("Usage: AcceptanceFixtures seed|verify <synthetic-workspace>");

string root = Path.GetFullPath(args[1]);
string keyDirectory = Path.Combine(root, "keys");
var pgp = new PgpService();
var signatures = new PgpSignatureService();
char[] passphrase = "synthetic installer acceptance only".ToCharArray();
const string message = "Synthetic message created before the application upgrade.";
try
{
    if (args[0] == "seed")
    {
        if (Directory.Exists(root) && Directory.EnumerateFileSystemEntries(root).Any())
            throw new IOException("Fixture generation requires an empty workspace.");
        Directory.CreateDirectory(root);
        KeyStoreLocation.CreateSecureDirectory(keyDirectory);
        var pair = await pgp.GenerateKeyPairAsync(new KeyGenerationOptions
        {
            Name = "Synthetic Upgrade User", Email = "upgrade@example.invalid",
            Algorithm = PgpKeyAlgorithm.Ed25519, Passphrase = passphrase,
            ExpirationDate = DateTime.UtcNow.AddYears(1)
        });
        var info = pgp.ReadPrivateKeyInfo(pair.PrivateKey, false);
        // The published 1.1.0 store used short-ID filenames and a JSON list cache.
        info.PublicKeyFile = "pub_" + info.KeyId + ".asc";
        info.PrivateKeyFile = "sec_" + info.KeyId + ".asc";
        info.HasPrivateKey = true;
        await Write(info.PublicKeyFile, pair.PublicKey);
        await Write(info.PrivateKeyFile, pair.PrivateKey);
        await Write("rev_" + info.Fingerprint + ".asc", pair.RevocationCertificate);
        await Write("index.json", JsonSerializer.Serialize(new[] { info }));
        await FileTransaction.WriteTextAsync(Path.Combine(root, "fingerprint.txt"), info.Fingerprint);
        await FileTransaction.WriteTextAsync(Path.Combine(root, "message.asc"), Payload(await pgp.EncryptTextAsync(message, pair.PublicKey, false)));
        await FileTransaction.WriteTextAsync(Path.Combine(root, "message.signed"), Payload(await signatures.SignTextAsync(message, pair.PrivateKey, false, passphrase)));
        Console.WriteLine("Synthetic legacy store, encrypted message and signature prepared.");
    }
    else
    {
        if (!File.Exists(Path.Combine(root, "fingerprint.txt"))) throw new IOException("No synthetic fixture was found.");
        string fingerprint = File.ReadAllText(Path.Combine(root, "fingerprint.txt"));
        var store = new KeyStoreService(pgp, keyDirectory);
        var key = store.GetAllKeys().Single();
        if (key.Fingerprint != fingerprint || !key.HasPrivateKey) throw new InvalidDataException("The upgraded store lost its identity or private key.");
        await CheckAccess(store);
        await store.ImportPrivateKeyAsync(store.GetKeyFilePath(fingerprint, true)!);
        var migrated = store.GetAllKeys().Single();
        if (!migrated.PublicKeyFile.Contains(fingerprint, StringComparison.Ordinal) ||
            migrated.PrivateKeyFile?.Contains(fingerprint, StringComparison.Ordinal) != true)
            throw new InvalidDataException("Reimport did not migrate legacy filenames.");
        string backup = Path.Combine(root, "verified-backup.zip");
        await store.ExportBackupAsync(backup);
        var restored = new KeyStoreService(pgp, Path.Combine(root, "restored"));
        if (await restored.RestoreBackupAsync(backup) != 1 || restored.GetAllKeys().Single().Fingerprint != fingerprint)
            throw new InvalidDataException("The restore lost its identity.");
        await CheckAccess(restored);
        await restored.ExportRevocationCertificateAsync(fingerprint, Path.Combine(root, "restored-revocation.asc"), []);
        Console.WriteLine("PASS: upgrade identity, legacy migration, historical decryption/signature, backup restore and recovery certificate.");

        async Task CheckAccess(IKeyStoreService source)
        {
            string clear = Payload(await pgp.DecryptTextAsync(File.ReadAllText(Path.Combine(root, "message.asc")),
                source.GetKeyFilePath(fingerprint, true)!, true, passphrase));
            if (clear != message) throw new InvalidDataException("Historical decryption changed the plaintext.");
            var verified = await signatures.VerifyTextAsync(File.ReadAllText(Path.Combine(root, "message.signed")),
                source.GetKeyFilePath(fingerprint, false)!, true);
            if (!verified.IsValid || verified.PrimaryFingerprint != fingerprint)
                throw new InvalidDataException("Historical signature verification failed.");
        }
    }
}
finally { Array.Clear(passphrase); }

Task Write(string name, string text) => FileTransaction.WriteTextAsync(Path.Combine(keyDirectory, name), text);
static string Payload(OperationResult result) => result.Success && result.Payload is { } payload
    ? payload : throw new InvalidDataException(result.Message);
