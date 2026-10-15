using System.Text;
using Org.BouncyCastle.Bcpg;
using Org.BouncyCastle.Bcpg.OpenPgp;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;
using PgpUtility.Models;
using PgpUtility.Services;

namespace PgpUtility.Tests;

public class KeyPolicyTests
{
    [Fact]
    public async Task A_certify_only_primary_uses_its_cross_certified_signing_subkey()
    {
        var pair = CreateSigningRing(crossCertify: true);
        var service = new PgpSignatureService();
        var signed = await service.SignTextAsync("a real signing subkey", pair.PrivateKey, false, Passphrase());
        signed.Success.Should().BeTrue(signed.Message);
        var verified = await service.VerifyTextAsync(signed.Payload!, pair.PublicKey, false);
        verified.IsValid.Should().BeTrue(verified.Message);
        verified.PrimaryFingerprint.Should().NotBe(verified.SigningFingerprint);
        verified.SignerUserId.Should().Be("Synthetic signing subkey");
    }

    [Fact]
    public async Task A_signing_subkey_without_cross_certification_is_not_usable()
    {
        var pair = CreateSigningRing(crossCertify: false);
        var service = new PgpSignatureService();
        var signed = await service.SignTextAsync("must refuse", pair.PrivateKey, false, Passphrase());
        signed.Success.Should().BeFalse();
        new PgpService().ReadPublicKeyInfo(pair.PublicKey, false).CanSign.Should().BeFalse();
    }

    [Fact]
    public async Task Expired_primary_and_subkey_certificates_block_new_operations()
    {
        var pair = CreateSigningRing(crossCertify: true, expired: true);
        var service = new PgpService();
        var info = service.ReadPublicKeyInfo(pair.PublicKey, false);
        info.ExpirationDate.Should().BeBefore(DateTime.UtcNow);
        info.CanSign.Should().BeFalse();
        var signed = await new PgpSignatureService().SignTextAsync("must refuse", pair.PrivateKey, false, Passphrase());
        signed.Success.Should().BeFalse();
    }

    [SkippableFact]
    public async Task Gpg_agrees_with_a_signature_from_the_selected_signing_subkey()
    {
        Skip.IfNot(GnuPgRunner.IsUsable, "gpg is not usable");
        var pair = CreateSigningRing(crossCertify: true);
        using var work = new TempWorkspace();
        using var gpg = new GnuPgRunner();
        string publicKey = work.Path("subkey-public.asc");
        File.WriteAllText(publicKey, pair.PublicKey);
        gpg.Run("--import", publicKey).All.Should().Contain("imported");
        var signed = await new PgpSignatureService().SignTextAsync("signed using the authorized subkey", pair.PrivateKey, false, Passphrase());
        signed.Success.Should().BeTrue(signed.Message);
        string message = work.Path("signed.asc");
        File.WriteAllText(message, signed.Payload);
        var verified = gpg.Run("--verify", message);
        verified.Ok.Should().BeTrue(verified.All);
    }

    [SkippableFact]
    public async Task An_offline_primary_export_from_gpg_can_sign_with_its_available_subkey()
    {
        Skip.IfNot(GnuPgRunner.CanUseSecretKeys, "gpg-agent is not usable");
        using var gpg = new GnuPgRunner();
        var generated = gpg.Run("--pinentry-mode", "loopback", "--passphrase", "synthetic",
            "--quick-generate-key", "Offline primary <offline@example.invalid>", "ed25519", "cert", "0");
        generated.Ok.Should().BeTrue(generated.All);
        string listing = gpg.Run("--with-colons", "--list-secret-keys").StandardOutput;
        string fingerprint = listing.Split('\n').First(line => line.StartsWith("fpr:", StringComparison.Ordinal)).Split(':')[9];
        var added = gpg.Run("--pinentry-mode", "loopback", "--passphrase", "synthetic", "--quick-add-key", fingerprint, "ed25519", "sign", "0");
        added.Ok.Should().BeTrue(added.All);
        var exported = gpg.Run("--pinentry-mode", "loopback", "--passphrase", "synthetic", "--armor", "--export-secret-subkeys", fingerprint);
        exported.Ok.Should().BeTrue(exported.All);
        var complete = gpg.Run("--pinentry-mode", "loopback", "--passphrase", "synthetic", "--armor", "--export-secret-keys", fingerprint);
        complete.Ok.Should().BeTrue(complete.All);
        using var work = new TempWorkspace();
        var store = new KeyStoreService(new PgpService(), work.Path("store"));
        await store.ImportKeyFromStringAsync(complete.StandardOutput, true);
        await store.ImportKeyFromStringAsync(exported.StandardOutput, true);
        using var stored = PgpUtilities.GetDecoderStream(File.OpenRead(store.GetKeyFilePath(fingerprint, true)!));
        new PgpSecretKeyRing(stored).GetSecretKey().IsPrivateKeyEmpty.Should().BeFalse();
        var publicKey = gpg.Run("--armor", "--export", fingerprint).StandardOutput;
        var service = new PgpSignatureService();
        var signed = await service.SignTextAsync("offline master is not needed", exported.StandardOutput, false, "synthetic".ToCharArray());
        signed.Success.Should().BeTrue(signed.Message);
        var verified = await service.VerifyTextAsync(signed.Payload!, publicKey, false);
        verified.IsValid.Should().BeTrue(verified.Message);
    }

    internal static GeneratedKeyPair CreateSigningRing(bool crossCertify, bool expired = false)
    {
        var random = new SecureRandom();
        DateTime created = expired ? DateTime.UtcNow.AddDays(-3) : DateTime.UtcNow;
        var generator = new Ed25519KeyPairGenerator();
        generator.Init(new Ed25519KeyGenerationParameters(random));
        var primary = new PgpKeyPair(PublicKeyAlgorithmTag.EdDsa_Legacy, generator.GenerateKeyPair(), created);
        var subkey = new PgpKeyPair(PublicKeyAlgorithmTag.EdDsa_Legacy, generator.GenerateKeyPair(), created);
        var primaryPackets = new PgpSignatureSubpacketGenerator();
        primaryPackets.SetSignatureCreationTime(false, created);
        primaryPackets.SetKeyFlags(false, PgpKeyFlags.CanCertify);
        if (expired) primaryPackets.SetKeyExpirationTime(false, 86400);
        var ring = new PgpKeyRingGenerator(PgpSignature.DefaultCertification, primary, "Synthetic signing subkey",
            SymmetricKeyAlgorithmTag.Aes256, HashAlgorithmTag.Sha256, true, Passphrase(), true, primaryPackets.Generate(), null, random);
        var subkeyPackets = new PgpSignatureSubpacketGenerator();
        subkeyPackets.SetSignatureCreationTime(false, created);
        subkeyPackets.SetKeyFlags(false, PgpKeyFlags.CanSign);
        if (expired) subkeyPackets.SetKeyExpirationTime(false, 86400);
        if (crossCertify) ring.AddSubKey(subkey, subkeyPackets.Generate(), null, HashAlgorithmTag.Sha256, HashAlgorithmTag.Sha256);
        else ring.AddSubKey(subkey, subkeyPackets.Generate(), null, HashAlgorithmTag.Sha256);
        string Armor(Action<Stream> write)
        {
            using var buffer = new MemoryStream();
            using (var armor = new ArmoredOutputStream(buffer)) write(armor);
            return Encoding.UTF8.GetString(buffer.ToArray());
        }
        return new(Armor(ring.GeneratePublicKeyRing().Encode), Armor(ring.GenerateSecretKeyRing().Encode), string.Empty);
    }
    private static char[] Passphrase() => "synthetic policy fixture".ToCharArray();
}
