using System.Text;
using PgpUtility.Models;

namespace PgpUtility.Services;

public static class KeyPairExportService
{
    public static async Task<IReadOnlyList<string>> SaveAsync(string directory, GeneratedKeyPair pair)
    {
        if (!System.IO.Directory.Exists(directory)) throw new IOException("Choose an existing backup folder.");
        var service = new PgpService();
        var publicKey = service.ReadPublicKeyInfo(pair.PublicKey, false);
        var secretKey = service.ReadPrivateKeyInfo(pair.PrivateKey, false);
        if (publicKey.Fingerprint != secretKey.Fingerprint) throw new ArgumentException("The public and private fingerprints do not match.");
        _ = new KeyLifecycleService().ApplyRevocation(pair.PublicKey, pair.RevocationCertificate);
        string prefix = publicKey.Fingerprint + "-" + Guid.NewGuid().ToString("N")[..8];
        var files = new[]
        {
            (Path.Combine(directory, prefix + "_public.asc"), pair.PublicKey),
            (Path.Combine(directory, prefix + "_private.asc"), pair.PrivateKey),
            (Path.Combine(directory, prefix + "_revocation.asc"), pair.RevocationCertificate)
        };
        var transactions = new List<FileTransaction>();
        var committed = new List<string>();
        try
        {
            foreach (var file in files)
            {
                var transaction = new FileTransaction(file.Item1);
                transactions.Add(transaction);
                await transaction.Stream.WriteAsync(Encoding.UTF8.GetBytes(file.Item2));
            }
            for (int i = 0; i < transactions.Count; i++)
            {
                transactions[i].Commit();
                committed.Add(files[i].Item1);
            }
            return committed;
        }
        catch
        {
            foreach (string file in committed) File.Delete(file);
            throw;
        }
        finally { foreach (var transaction in transactions) transaction.Dispose(); }
    }
}
