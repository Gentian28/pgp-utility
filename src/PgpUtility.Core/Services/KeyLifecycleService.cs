using System.Text;
using Org.BouncyCastle.Bcpg;
using Org.BouncyCastle.Bcpg.OpenPgp;
using Org.BouncyCastle.Security;

namespace PgpUtility.Services;

public sealed class KeyLifecycleService
{
    public string ApplyRevocation(string publicKey, string certificate)
    {
        CryptoInputLimits.CheckText(publicKey);
        CryptoInputLimits.CheckText(certificate);
        using var source = new MemoryStream(Encoding.UTF8.GetBytes(publicKey));
        var ring = PgpKeyValidation.ReadPublic(source);
        var identity = new PgpKeyValidation(ring);
        using var input = new MemoryStream(Encoding.UTF8.GetBytes(certificate));
        using var decoded = PgpUtilities.GetDecoderStream(input);
        var factory = new PgpObjectFactory(decoded);
        if (factory.NextPgpObject() is not PgpSignatureList signatures || signatures.Count != 1 || factory.NextPgpObject() is not null)
            throw new PgpException("Choose a single key revocation certificate.");
        var signature = signatures[0];
        if (signature.SignatureType != PgpSignature.KeyRevocation || signature.CreationTime > DateTime.UtcNow)
            throw new PgpException("This is not a current key revocation certificate.");
        signature.InitVerify(identity.Primary);
        if (!signature.VerifyCertification(identity.Primary))
            throw new PgpException("This revocation certificate does not belong to the selected fingerprint.");
        ring = PgpPublicKeyRing.InsertPublicKey(ring, PgpPublicKey.AddCertification(identity.Primary, signature));
        if (!new PgpKeyValidation(ring).IsRevoked)
            throw new PgpException("This certificate contains unsupported revocation semantics and was not applied.");
        return KeyStoreService.Armor(ring.Encode);
    }

    public async Task<string> ExtendExpiryAsync(string privateKey, char[] passphrase, DateTime expiry,
        CancellationToken cancellationToken = default)
    {
        char[] owned = (char[])passphrase.Clone();
        try
        {
            using var input = new MemoryStream(Encoding.UTF8.GetBytes(privateKey));
            var secret = PgpKeyValidation.ReadSecret(input);
            var publicRing = PgpKeyValidation.PublicRing(secret);
            var identity = new PgpKeyValidation(publicRing);
            if (identity.IsRevoked) throw new PgpException("A revoked key cannot be renewed.");
            expiry = expiry.ToUniversalTime();
            if (expiry <= DateTime.UtcNow.AddMinutes(1)) throw new ArgumentException("Choose a future expiry date.");
            if (identity.ExpirationDate is { } previous && expiry <= previous)
                throw new ArgumentException("Choose an expiry later than the key's existing expiry.");
            // OpenPGP timestamps have one-second precision. Avoid an ambiguous same-second
            // self-certification when a newly generated key is immediately renewed.
            DateTime last = identity.IdentityCertifications.Values
                .Concat(publicRing.GetPublicKeys().Where(k => !k.IsMasterKey).Select(identity.CertificationFor))
                .Max(s => s.CreationTime);
            var wait = last.AddSeconds(1) - DateTime.UtcNow;
            if (wait > TimeSpan.Zero) await Task.Delay(wait, cancellationToken);
            return await Task.Run(() =>
            {
                cancellationToken.ThrowIfCancellationRequested();
                var master = secret.GetSecretKey();
                if (master.IsPrivateKeyEmpty) throw new PgpException("Renewal needs the private primary key, which is not available in this export.");
                var signingKey = PgpKeyRoles.ExtractPrivateKey(master, owned);
                var updated = identity.Primary;
                foreach (var certification in identity.IdentityCertifications)
                {
                    var generator = new PgpSignatureGenerator(updated.Algorithm, HashAlgorithmTag.Sha256);
                    generator.InitSign(certification.Value.SignatureType, signingKey);
                    generator.SetHashedSubpackets(RenewPackets(certification.Value, updated.CreationTime, expiry));
                    updated = PgpPublicKey.AddCertification(updated, certification.Key, generator.GenerateCertification(certification.Key, updated));
                }
                publicRing = PgpPublicKeyRing.InsertPublicKey(publicRing, updated);
                foreach (var key in publicRing.GetPublicKeys().Where(k => !k.IsMasterKey).ToArray())
                {
                    var generator = new PgpSignatureGenerator(updated.Algorithm, HashAlgorithmTag.Sha256);
                    generator.InitSign(PgpSignature.SubkeyBinding, signingKey);
                    var previous = identity.CertificationFor(key);
                    generator.SetHashedSubpackets(RenewPackets(previous, key.CreationTime, expiry));
                    // Older tools store the independently verified cross-signature unhashed.
                    // Keep it when issuing the replacement binding, without copying other hints.
                    var embedded = previous.GetUnhashedSubPackets()?.ToArray()
                        .Where(p => p.SubpacketType == SignatureSubpacketTag.EmbeddedSignature).ToArray() ?? [];
                    generator.SetUnhashedSubpackets(PgpSignatureSubpacketVector.FromSubpackets(embedded));
                    var renewed = PgpPublicKey.AddCertification(key, generator.GenerateCertification(updated, key));
                    publicRing = PgpPublicKeyRing.InsertPublicKey(publicRing, renewed);
                }
                _ = new PgpKeyValidation(publicRing);
                var result = PgpSecretKeyRing.ReplacePublicKeys(secret, publicRing);
                return KeyStoreService.Armor(result.Encode);
            }, cancellationToken);
        }
        finally { Array.Clear(owned); }
    }

    public async Task<string> ChangePassphraseAsync(string privateKey, char[] oldPassphrase, char[] newPassphrase,
        CancellationToken cancellationToken = default)
    {
        if (newPassphrase.Length == 0) throw new ArgumentException("Enter a new passphrase to protect the private key.");
        char[] oldOwned = (char[])oldPassphrase.Clone();
        char[] newOwned = (char[])newPassphrase.Clone();
        try
        {
            return await Task.Run(() =>
            {
                using var input = new MemoryStream(Encoding.UTF8.GetBytes(privateKey));
                var ring = PgpKeyValidation.ReadSecret(input);
                _ = new PgpKeyValidation(PgpKeyValidation.PublicRing(ring));
                foreach (var key in ring.GetSecretKeys().Where(k => !k.IsPrivateKeyEmpty).ToArray())
                {
                    cancellationToken.ThrowIfCancellationRequested();
                    // Validate the passphrase through the shared UTF-8/legacy decoder first.
                    _ = PgpKeyRoles.ExtractPrivateKey(key, oldOwned);
                    PgpSecretKey changed;
                    try { changed = PgpSecretKey.CopyWithNewPasswordUtf8(key, oldOwned, newOwned, SymmetricKeyAlgorithmTag.Aes256, new SecureRandom()); }
                    catch (PgpException)
                    {
                        byte[] oldBytes = oldOwned.Select(c => (byte)c).ToArray();
                        byte[] newBytes = Encoding.UTF8.GetBytes(newOwned);
                        try { changed = PgpSecretKey.CopyWithNewPasswordRaw(key, oldBytes, newBytes, SymmetricKeyAlgorithmTag.Aes256, new SecureRandom()); }
                        finally { Array.Clear(oldBytes); Array.Clear(newBytes); }
                    }
                    ring = PgpSecretKeyRing.InsertSecretKey(ring, changed);
                }
                return KeyStoreService.Armor(ring.Encode);
            }, cancellationToken);
        }
        finally { Array.Clear(oldOwned); Array.Clear(newOwned); }
    }

    private static PgpSignatureSubpacketVector RenewPackets(PgpSignature previous, DateTime keyCreation, DateTime expiry)
    {
        // BouncyCastle's Set methods append, rather than replace. Remove the old values first
        // so consumers cannot keep reading the old creation time or expiry from a duplicate.
        var retained = previous.GetHashedSubPackets().ToArray().Where(p => (int)p.SubpacketType is not (2 or 9)).ToArray();
        var packets = new PgpSignatureSubpacketGenerator(PgpSignatureSubpacketVector.FromSubpackets(retained));
        packets.SetSignatureCreationTime(false, DateTime.UtcNow);
        packets.SetKeyExpirationTime(false, (long)(expiry - keyCreation).TotalSeconds);
        return packets.Generate();
    }
}
