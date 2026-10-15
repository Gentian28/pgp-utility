using System.Security.AccessControl;
using System.Security.Principal;
using Org.BouncyCastle.Bcpg;
using Org.BouncyCastle.Bcpg.OpenPgp;
using PgpUtility.Services;

namespace PgpUtility.Tests;

[Collection(KeyCollection.Name)]
public class AdditionalSafetyTests(GeneratedKeys keys)
{
    [SkippableFact]
    public async Task An_encryption_only_private_export_is_not_offered_for_signing()
    {
        Skip.IfNot(GnuPgRunner.CanUseSecretKeys, "gpg-agent is not usable");
        using var work = new TempWorkspace();
        using var gpg = new GnuPgRunner();
        string full = work.WriteFile("secret.asc", System.Text.Encoding.UTF8.GetBytes(keys.Ed25519Private));
        var imported = gpg.Run("--pinentry-mode", "loopback", "--passphrase", GeneratedKeys.PassphraseText, "--import", full);
        imported.Ok.Should().BeTrue(imported.All);
        string fingerprint = keys.Service.ReadPrivateKeyInfo(keys.Ed25519Private, false).Fingerprint;
        var exported = gpg.Run("--pinentry-mode", "loopback", "--passphrase", GeneratedKeys.PassphraseText, "--armor", "--export-secret-subkeys", fingerprint);
        exported.Ok.Should().BeTrue(exported.All);
        var info = keys.Service.ReadPrivateKeyInfo(exported.StandardOutput, false);
        info.HasPrivateKey.Should().BeTrue();
        info.CanSign.Should().BeFalse();
        var store = new KeyStoreService(keys.Service, work.Path("store"));
        var stored = await store.ImportKeyFromStringAsync(exported.StandardOutput, true);
        stored.CanSign.Should().BeFalse();
        var signed = await keys.Signatures.SignTextAsync("must refuse", exported.StandardOutput, false, GeneratedKeys.Passphrase());
        signed.Success.Should().BeFalse();
    }

    [Fact]
    public void Staging_files_are_private_from_their_first_open()
    {
        using var work = new TempWorkspace();
        using var transaction = new FileTransaction(work.Path("output"));
        string staging = Directory.GetFiles(work.Root, ".pgputility-*.partial").Single();
        if (OperatingSystem.IsWindows())
        {
            var security = new FileInfo(staging).GetAccessControl();
            security.AreAccessRulesProtected.Should().BeTrue();
            var rules = security.GetAccessRules(true, true, typeof(SecurityIdentifier)).Cast<FileSystemAccessRule>().ToArray();
            rules.Should().ContainSingle();
            rules[0].IdentityReference.Should().Be(WindowsIdentity.GetCurrent().User);
            rules[0].AccessControlType.Should().Be(AccessControlType.Allow);
        }
        else File.GetUnixFileMode(staging).Should().Be(UnixFileMode.UserRead | UnixFileMode.UserWrite);
    }

    [Fact]
    public async Task Compressed_text_cannot_expand_without_a_memory_limit()
    {
        using var work = new TempWorkspace();
        string input = work.WriteFile("input.txt", new byte[17 * 1024 * 1024]);
        string output = work.Path("encrypted.asc");
        var encrypted = await keys.Service.EncryptFileAsync(input, output, keys.Ed25519Public, false, true);
        encrypted.Success.Should().BeTrue(encrypted.Message);
        var decrypted = await keys.Service.DecryptTextAsync(File.ReadAllText(output), keys.Ed25519Private, false, GeneratedKeys.Passphrase());
        decrypted.Success.Should().BeFalse();
        decrypted.Payload.Should().BeNull();
        decrypted.Message.Should().Contain("16 MiB");
    }

    [Fact]
    public async Task Cancellation_before_start_returns_a_cancellation_result()
    {
        using var cancellation = new CancellationTokenSource();
        cancellation.Cancel();
        var result = await keys.Service.DecryptTextAsync("irrelevant", "irrelevant", false, [], cancellation.Token);
        result.IsCanceled.Should().BeTrue();
        result.Payload.Should().BeNull();
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task Weak_digests_and_unhandled_critical_requirements_cannot_get_a_good_verdict(bool criticalNotation)
    {
        using var work = new TempWorkspace();
        using var keyInput = new MemoryStream(System.Text.Encoding.UTF8.GetBytes(keys.RsaPrivate));
        var secret = new PgpSecretKeyRing(PgpUtilities.GetDecoderStream(keyInput)).GetSecretKey();
        var generator = new PgpSignatureGenerator(secret.PublicKey.Algorithm, criticalNotation ? HashAlgorithmTag.Sha256 : HashAlgorithmTag.Sha1);
        generator.InitSign(PgpSignature.BinaryDocument, secret.ExtractPrivateKeyUtf8(GeneratedKeys.Passphrase()));
        if (criticalNotation)
        {
            var packets = new PgpSignatureSubpacketGenerator();
            packets.AddNotationData(true, true, "test@example.invalid", "unsupported requirements");
            generator.SetHashedSubpackets(packets.Generate());
        }
        byte[] bytes = "synthetic document"u8.ToArray();
        generator.Update(bytes);
        string input = work.WriteFile("document.txt", bytes);
        string signature = work.WriteFile("document.sig", generator.Generate().GetEncoded());
        var result = await keys.Signatures.VerifyFileAsync(input, signature, keys.RsaPublic, false);
        result.Completed.Should().BeFalse();
        result.IsValid.Should().BeFalse();
    }
}
