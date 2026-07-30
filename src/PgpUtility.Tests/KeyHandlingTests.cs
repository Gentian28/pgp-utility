using PgpUtility.Models;
using PgpUtility.Services;

namespace PgpUtility.Tests;

[Collection(KeyCollection.Name)]
public class KeyHandlingTests
{
    private readonly GeneratedKeys _keys;

    public KeyHandlingTests(GeneratedKeys keys) => _keys = keys;

    [Fact]
    public void The_public_key_extracted_from_a_private_key_is_the_same_key()
    {
        string extracted = _keys.Service.ExtractPublicKeyFromPrivateKey(_keys.Ed25519Private, isFilePath: false);

        PgpKeyInfo fromExtracted = _keys.Service.ReadPublicKeyInfo(extracted, isFilePath: false);
        PgpKeyInfo fromOriginal = _keys.Service.ReadPublicKeyInfo(_keys.Ed25519Public, isFilePath: false);

        fromExtracted.Fingerprint.Should().Be(fromOriginal.Fingerprint);
        fromExtracted.KeyId.Should().Be(fromOriginal.KeyId);
        fromExtracted.UserId.Should().Be(fromOriginal.UserId);
    }

    [Fact]
    public async Task An_extracted_public_key_can_actually_encrypt_to_the_original_private_key()
    {
        // Matching fingerprints prove the master key survived. They do not prove the encryption
        // subkey came with it, which is the half that matters for Ed25519.
        using var work = new TempWorkspace();
        string extracted = _keys.Service.ExtractPublicKeyFromPrivateKey(_keys.Ed25519Private, isFilePath: false);

        byte[] original = "round trip through an extracted key"u8.ToArray();
        string plain = work.WriteFile("plain.bin", original);

        OperationResult encrypted = await _keys.Service.EncryptFileAsync(
            plain, work.Path("c.pgp"), extracted, isFilePath: false, armor: true);
        encrypted.Success.Should().BeTrue(encrypted.Message);

        OperationResult decrypted = await _keys.Service.DecryptFileAsync(
            work.Path("c.pgp"), work.Path("out.bin"), _keys.Ed25519Private, isFilePath: false, GeneratedKeys.Passphrase());
        decrypted.Success.Should().BeTrue(decrypted.Message);

        File.ReadAllBytes(work.Path("out.bin")).Should().Equal(original);
    }

    [Fact]
    public void Reading_key_info_reports_the_identity_and_algorithm()
    {
        PgpKeyInfo ed = _keys.Service.ReadPublicKeyInfo(_keys.Ed25519Public, isFilePath: false);
        ed.UserId.Should().Be("Ed Tester <ed@example.com>");
        ed.Algorithm.Should().Contain("EdDsa");
        ed.HasPrivateKey.Should().BeFalse();
        ed.Fingerprint.Should().MatchRegex("^[0-9A-F]{40}$");

        PgpKeyInfo rsa = _keys.Service.ReadPublicKeyInfo(_keys.RsaPublic, isFilePath: false);
        rsa.Algorithm.Should().Contain("Rsa");
        rsa.KeySize.Should().Be(2048);
    }

    [Fact]
    public void Reading_private_key_info_needs_no_passphrase()
    {
        // Everything reported here lives in the unencrypted public half of the secret key packet.
        PgpKeyInfo info = _keys.Service.ReadPrivateKeyInfo(_keys.Ed25519Private, isFilePath: false);

        info.HasPrivateKey.Should().BeTrue();
        info.KeyId.Should().Be(_keys.Service.ReadPublicKeyInfo(_keys.Ed25519Public, isFilePath: false).KeyId);
    }

    [Fact]
    public async Task Importing_a_private_key_into_the_store_also_stores_its_public_half()
    {
        using var work = new TempWorkspace();
        var store = new KeyStoreService(_keys.Service, work.Path("keys"));

        string privateKeyFile = work.Path("sec.asc");
        await File.WriteAllTextAsync(privateKeyFile, _keys.Ed25519Private);

        PgpKeyInfo imported = await store.ImportPrivateKeyAsync(privateKeyFile);

        imported.HasPrivateKey.Should().BeTrue();
        imported.HasPublicKey.Should().BeTrue();

        string? publicPath = store.GetKeyFilePath(imported.KeyId, privateKey: false);
        publicPath.Should().NotBeNull();

        PgpKeyInfo stored = _keys.Service.ReadPublicKeyInfo(publicPath!, isFilePath: true);
        stored.Fingerprint.Should().Be(imported.Fingerprint);
    }

    [Fact]
    public async Task A_key_imported_into_the_store_survives_a_reload()
    {
        using var work = new TempWorkspace();
        string keysDirectory = work.Path("keys");

        var first = new KeyStoreService(_keys.Service, keysDirectory);
        PgpKeyInfo imported = await first.ImportKeyFromStringAsync(_keys.Ed25519Public, isPrivate: false);

        // A second instance reads the index off disk, which is what happens on the next launch.
        var second = new KeyStoreService(_keys.Service, keysDirectory);
        second.GetAllKeys().Should().ContainSingle(k => k.KeyId == imported.KeyId);
    }

    [Fact]
    public async Task Deleting_a_key_removes_it_from_the_index_and_from_disk()
    {
        using var work = new TempWorkspace();
        string keysDirectory = work.Path("keys");
        var store = new KeyStoreService(_keys.Service, keysDirectory);

        PgpKeyInfo imported = await store.ImportKeyFromStringAsync(_keys.Ed25519Private, isPrivate: true);
        string? path = store.GetKeyFilePath(imported.KeyId, privateKey: true);
        path.Should().NotBeNull();

        await store.DeleteKeyAsync(imported.KeyId);

        store.GetAllKeys().Should().BeEmpty();
        File.Exists(path!).Should().BeFalse();
    }
}
