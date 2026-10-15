using System.Text;
using Org.BouncyCastle.Bcpg;
using Org.BouncyCastle.Bcpg.OpenPgp;
using PgpUtility.Services;

namespace PgpUtility.Tests;

[Collection(KeyCollection.Name)]
public class ReleaseReviewTests(GeneratedKeys keys)
{
    [Theory]
    [InlineData(PgpSignature.PositiveCertification)]
    [InlineData(PgpSignature.SubkeyBinding)]
    [InlineData(PgpSignature.KeyRevocation)]
    public async Task Authenticated_critical_requirements_cannot_fall_back_to_an_older_certificate(int type)
    {
        var ring = SafetyRegressionTests.Read(keys.Ed25519Public);
        using var input = new MemoryStream(Encoding.UTF8.GetBytes(keys.Ed25519Private));
        var secret = new PgpSecretKeyRing(PgpUtilities.GetDecoderStream(input)).GetSecretKey();
        var generator = new PgpSignatureGenerator(secret.PublicKey.Algorithm, HashAlgorithmTag.Sha256);
        generator.InitSign(type, secret.ExtractPrivateKeyUtf8(GeneratedKeys.Passphrase()));
        var packets = new PgpSignatureSubpacketGenerator();
        packets.AddNotationData(true, true, "policy@example.invalid", "require an unsupported policy");
        generator.SetHashedSubpackets(packets.Generate());
        PgpPublicKey changed;
        if (type == PgpSignature.SubkeyBinding)
        {
            var subkey = ring.GetPublicKeys().First(k => !k.IsMasterKey);
            changed = PgpPublicKey.AddCertification(subkey, generator.GenerateCertification(ring.GetPublicKey(), subkey));
        }
        else if (type == PgpSignature.PositiveCertification)
        {
            string id = ring.GetPublicKey().GetUserIds().First();
            changed = PgpPublicKey.AddCertification(ring.GetPublicKey(), id, generator.GenerateCertification(id, ring.GetPublicKey()));
        }
        else changed = PgpPublicKey.AddCertification(ring.GetPublicKey(), generator.GenerateCertification(ring.GetPublicKey()));
        ring = PgpPublicKeyRing.InsertPublicKey(ring, changed);
        string text = SafetyRegressionTests.Encode(ring.GetPublicKeys());
        var encrypted = await keys.Service.EncryptTextAsync("must not ignore critical semantics", text, false);
        encrypted.Success.Should().BeFalse();
        encrypted.Payload.Should().BeNull();
    }

    [Fact]
    public async Task Restoring_or_reimporting_an_old_private_copy_keeps_the_current_private_protection()
    {
        using var work = new TempWorkspace();
        var store = new KeyStoreService(keys.Service, work.Path("store"));
        var key = await store.ImportKeyFromStringAsync(keys.Ed25519Private, true);
        string oldBackup = work.Path("old.zip");
        await store.ExportBackupAsync(oldBackup);
        const string next = "synthetic new current passphrase";
        await store.ChangePassphraseAsync(key.Fingerprint, GeneratedKeys.Passphrase(), next.ToCharArray());
        await store.ImportKeyFromStringAsync(keys.Ed25519Private, true);
        await store.RestoreBackupAsync(oldBackup);
        var encrypted = await keys.Service.EncryptTextAsync("preserve current access", keys.Ed25519Public, false);
        var decrypted = await keys.Service.DecryptTextAsync(encrypted.Payload!, store.GetKeyFilePath(key.Fingerprint, true)!, true, next.ToCharArray());
        decrypted.Payload.Should().Be("preserve current access");
    }

    [Fact]
    public async Task A_damaged_stored_recovery_certificate_cannot_be_exported_as_a_working_backup()
    {
        using var work = new TempWorkspace();
        var store = new KeyStoreService(keys.Service, work.Path("store"));
        var key = await store.ImportKeyFromStringAsync(keys.Ed25519Private, true);
        File.WriteAllText(Path.Combine(store.Directory, "rev_" + key.Fingerprint + ".asc"), keys.Rsa.RevocationCertificate);
        string output = work.Path("backup.zip");
        Func<Task> backup = () => store.ExportBackupAsync(output);
        await backup.Should().ThrowAsync<PgpException>();
        File.Exists(output).Should().BeFalse();
        Func<Task> export = () => store.ExportRevocationCertificateAsync(key.Fingerprint, work.Path("revocation.asc"), []);
        await export.Should().ThrowAsync<PgpException>();
        File.Exists(work.Path("revocation.asc")).Should().BeFalse();
    }

    [Fact]
    public async Task An_oversized_store_cannot_produce_a_backup_the_restorer_will_refuse()
    {
        using var work = new TempWorkspace();
        var store = new KeyStoreService(keys.Service, work.Path("store"));
        var key = await store.ImportKeyFromStringAsync(keys.Ed25519Private, true);
        using (var oversized = File.Create(Path.Combine(store.Directory, "rev_" + key.Fingerprint + ".asc")))
            oversized.SetLength(16 * 1024 * 1024 + 1);
        string output = work.Path("backup.zip");
        File.WriteAllText(output, "existing backup");
        Func<Task> backup = () => store.ExportBackupAsync(output);
        await backup.Should().ThrowAsync<InvalidDataException>();
        File.ReadAllText(output).Should().Be("existing backup");
    }
}
