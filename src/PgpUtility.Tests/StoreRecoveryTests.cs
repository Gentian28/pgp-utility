using System.Text;
using Org.BouncyCastle.Bcpg;
using Org.BouncyCastle.Bcpg.OpenPgp;
using PgpUtility.Services;

namespace PgpUtility.Tests;

[Collection(KeyCollection.Name)]
public class StoreRecoveryTests(GeneratedKeys keys)
{
    [Fact]
    public async Task A_failed_index_commit_rolls_back_a_private_passphrase_change()
    {
        using var work = new TempWorkspace();
        var store = new KeyStoreService(keys.Service, work.Path("keys"));
        var key = await store.ImportKeyFromStringAsync(keys.Ed25519Private, true);
        string privatePath = store.GetKeyFilePath(key.Fingerprint, true)!;
        byte[] original = File.ReadAllBytes(privatePath);
        string blocked = Path.Combine(store.Directory, "index.json.bak");
        File.Delete(blocked);
        Directory.CreateDirectory(blocked);
        Func<Task> change = () => store.ChangePassphraseAsync(key.Fingerprint, GeneratedKeys.Passphrase(), "synthetic new password".ToCharArray());
        var failure = await Record.ExceptionAsync(change);
        (failure is IOException or UnauthorizedAccessException).Should().BeTrue();
        File.ReadAllBytes(privatePath).Should().Equal(original);
        var encrypted = await keys.Service.EncryptTextAsync("still accessible", keys.Ed25519Public, false);
        var decrypted = await keys.Service.DecryptTextAsync(encrypted.Payload!, privatePath, true, GeneratedKeys.Passphrase());
        decrypted.Payload.Should().Be("still accessible");
    }

    [Fact]
    public async Task Canonical_private_material_takes_precedence_over_a_leftover_legacy_alias()
    {
        using var work = new TempWorkspace();
        var store = new KeyStoreService(keys.Service, work.Path("keys"));
        var key = await store.ImportKeyFromStringAsync(keys.Ed25519Private, true);
        const string next = "synthetic replacement";
        await store.ChangePassphraseAsync(key.Fingerprint, GeneratedKeys.Passphrase(), next.ToCharArray());
        File.WriteAllText(Path.Combine(store.Directory, "sec_zz_legacy.asc"), keys.Ed25519Private);
        var encrypted = await keys.Service.EncryptTextAsync("current private key", keys.Ed25519Public, false);
        var decrypted = await keys.Service.DecryptTextAsync(encrypted.Payload!, store.GetKeyFilePath(key.Fingerprint, true)!, true, next.ToCharArray());
        decrypted.Payload.Should().Be("current private key");
    }

    [Fact]
    public async Task Two_instances_cannot_lose_each_others_imports()
    {
        using var work = new TempWorkspace();
        var first = new KeyStoreService(keys.Service, work.Path("keys"));
        var second = new KeyStoreService(keys.Service, work.Path("keys"));
        await Task.WhenAll(first.ImportKeyFromStringAsync(keys.Ed25519Public, false), second.ImportKeyFromStringAsync(keys.RsaPublic, false));
        new KeyStoreService(keys.Service, work.Path("keys")).GetAllKeys().Should().HaveCount(2);
        first.GetAllKeys().Should().HaveCount(2);
    }

    [Fact]
    public async Task A_corrupt_index_is_preserved_and_rebuilt_without_losing_private_keys()
    {
        using var work = new TempWorkspace();
        string directory = work.Path("keys");
        var store = new KeyStoreService(keys.Service, directory);
        var key = await store.ImportKeyFromStringAsync(keys.Ed25519Private, true);
        await File.WriteAllTextAsync(Path.Combine(directory, "index.json"), "[");
        var recovered = new KeyStoreService(keys.Service, directory);
        recovered.GetAllKeys().Should().ContainSingle(k => k.Fingerprint == key.Fingerprint && k.HasPrivateKey);
        recovered.Warnings.Should().NotBeEmpty();
        Directory.GetFiles(directory, "index.corrupt.*.json").Should().ContainSingle();
        var encrypted = await keys.Service.EncryptTextAsync("still accessible", keys.Ed25519Public, false);
        var decrypted = await keys.Service.DecryptTextAsync(encrypted.Payload!, recovered.GetKeyFilePath(key.Fingerprint, true)!, true, GeneratedKeys.Passphrase());
        decrypted.Payload.Should().Be("still accessible");
    }

    [Fact]
    public async Task An_old_public_import_cannot_undo_revocation_or_keep_the_secret_ring_live()
    {
        using var work = new TempWorkspace();
        var store = new KeyStoreService(keys.Service, work.Path("keys"));
        var key = await store.ImportKeyFromStringAsync(keys.Ed25519Private, true);
        var ring = SafetyRegressionTests.Read(keys.Ed25519Public);
        var packets = (PgpSignatureList)new PgpObjectFactory(PgpUtilities.GetDecoderStream(
            new MemoryStream(Encoding.UTF8.GetBytes(keys.Ed25519.RevocationCertificate)))).NextPgpObject();
        var revoked = PgpPublicKey.AddCertification(ring.GetPublicKey(), packets[0]);
        string update = SafetyRegressionTests.Encode(new[] { revoked }.Concat(ring.GetPublicKeys().Where(k => !k.IsMasterKey)));
        await store.ImportKeyFromStringAsync(update, false);
        await store.ImportKeyFromStringAsync(keys.Ed25519Public, false);
        store.GetAllKeys().Single().IsRevoked.Should().BeTrue();
        string secret = store.GetKeyFilePath(key.Fingerprint, true)!;
        var signed = await keys.Signatures.SignTextAsync("must refuse", secret, true, GeneratedKeys.Passphrase());
        signed.Success.Should().BeFalse();
    }

    [Fact]
    public async Task A_readonly_private_file_is_not_hidden_by_a_successful_deletion()
    {
        using var work = new TempWorkspace();
        var store = new KeyStoreService(keys.Service, work.Path("keys"));
        var key = await store.ImportKeyFromStringAsync(keys.Ed25519Private, true);
        string secret = store.GetKeyFilePath(key.Fingerprint, true)!;
        File.SetAttributes(secret, FileAttributes.ReadOnly);
        try
        {
            Func<Task> remove = () => store.DeleteKeyAsync(key.Fingerprint);
            await remove.Should().ThrowAsync<IOException>();
            store.GetAllKeys().Should().ContainSingle(k => k.HasPrivateKey);
            File.Exists(secret).Should().BeTrue();
        }
        finally { File.SetAttributes(secret, FileAttributes.Normal); }
    }

    [Fact]
    public async Task Legacy_key_id_files_are_migrated_on_import_and_do_not_resurrect_after_delete()
    {
        using var work = new TempWorkspace();
        string directory = work.Path("keys");
        Directory.CreateDirectory(directory);
        var info = keys.Service.ReadPublicKeyInfo(keys.Ed25519Public, false);
        string legacy = Path.Combine(directory, "pub_" + info.KeyId + ".asc");
        await File.WriteAllTextAsync(legacy, keys.Ed25519Public);
        var store = new KeyStoreService(keys.Service, directory);
        var imported = await store.ImportKeyFromStringAsync(keys.Ed25519Private, true);
        imported.PublicKeyFile.Should().Contain(info.Fingerprint);
        File.Exists(legacy).Should().BeFalse();
        await store.DeleteKeyAsync(info.Fingerprint);
        new KeyStoreService(keys.Service, directory).GetAllKeys().Should().BeEmpty();
    }

    [Fact]
    public async Task A_public_only_contact_has_no_private_key_path()
    {
        using var work = new TempWorkspace();
        var store = new KeyStoreService(keys.Service, work.Path("keys"));
        var key = await store.ImportKeyFromStringAsync(keys.Ed25519Public, false);
        store.GetKeyFilePath(key.Fingerprint, true).Should().BeNull();
    }

    [Fact]
    public async Task A_binary_import_is_normalized_to_armored_text()
    {
        using var work = new TempWorkspace();
        var ring = SafetyRegressionTests.Read(keys.Ed25519Public);
        string binary = work.WriteFile("binary.gpg", ring.GetEncoded());
        var store = new KeyStoreService(keys.Service, work.Path("keys"));
        var key = await store.ImportPublicKeyAsync(binary);
        File.ReadAllText(store.GetKeyFilePath(key.Fingerprint, false)!).Should().StartWith("-----BEGIN PGP PUBLIC KEY BLOCK-----");
    }
}
