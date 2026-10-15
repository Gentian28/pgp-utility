using System.Text;

namespace PgpUtility.Tests;

[Collection(KeyCollection.Name)]
public class SigningInteropTests(GeneratedKeys keys)
{
    [SkippableTheory]
    [InlineData("Unicode trailing NBSP\u00a0")]
    [InlineData("- first\rsecond\n\nlast\n")]
    public async Task Gpg_verifies_our_cleartext_signature(string text)
    {
        Skip.IfNot(GnuPgRunner.IsUsable, "gpg is not usable");
        using var work = new TempWorkspace();
        using var gpg = new GnuPgRunner();
        string publicKey = work.Path("pub.asc");
        File.WriteAllText(publicKey, keys.Ed25519Public);
        gpg.Run("--import", publicKey).All.Should().Contain("imported");
        var signed = await keys.Signatures.SignTextAsync(text, keys.Ed25519Private, false, GeneratedKeys.Passphrase());
        string message = work.Path("message.asc");
        File.WriteAllText(message, signed.Payload);
        var verified = gpg.Run("--verify", message);
        verified.Ok.Should().BeTrue(verified.All);
        verified.All.Should().Contain("Good signature");
    }

    [SkippableFact]
    public async Task We_verify_gpg_cleartext_and_detached_signatures()
    {
        Skip.IfNot(GnuPgRunner.CanUseSecretKeys, "gpg-agent is not usable");
        using var work = new TempWorkspace();
        using var gpg = new GnuPgRunner();
        string secret = work.Path("sec.asc");
        File.WriteAllText(secret, keys.Ed25519Private);
        gpg.Run("--pinentry-mode", "loopback", "--passphrase", GeneratedKeys.PassphraseText, "--import", secret).Ok.Should().BeTrue();
        string message = work.WriteFile("message.txt", Encoding.UTF8.GetBytes("- signed by gpg\nUnicode NBSP\u00a0\nlast line\n"));
        string signedPath = work.Path("message.asc");
        var signed = gpg.Run("--pinentry-mode", "loopback", "--passphrase", GeneratedKeys.PassphraseText,
            "--armor", "--output", signedPath, "--clearsign", message);
        signed.Ok.Should().BeTrue(signed.All);
        var textResult = await keys.Signatures.VerifyTextAsync(File.ReadAllText(signedPath), keys.Ed25519Public, false);
        textResult.IsValid.Should().BeTrue(textResult.Message);
        string signature = work.Path("message.sig");
        var detached = gpg.Run("--pinentry-mode", "loopback", "--passphrase", GeneratedKeys.PassphraseText,
            "--output", signature, "--detach-sign", message);
        detached.Ok.Should().BeTrue(detached.All);
        var result = await keys.Signatures.VerifyFileAsync(message, signature, keys.Ed25519Public, false);
        result.IsValid.Should().BeTrue(result.Message);
        result.PrimaryFingerprint.Should().Be(keys.Service.ReadPublicKeyInfo(keys.Ed25519Public, false).Fingerprint);
    }

    [SkippableFact]
    public async Task Gpg_verifies_our_detached_signature()
    {
        Skip.IfNot(GnuPgRunner.IsUsable, "gpg is not usable");
        using var work = new TempWorkspace();
        using var gpg = new GnuPgRunner();
        string publicKey = work.Path("pub.asc");
        File.WriteAllText(publicKey, keys.Ed25519Public);
        gpg.Run("--import", publicKey);
        string message = work.WriteFile("message.txt", "original bytes"u8.ToArray());
        string signature = work.Path("message.sig");
        var signed = await keys.Signatures.SignFileAsync(message, signature, keys.Ed25519Private, false, GeneratedKeys.Passphrase(), false);
        signed.Success.Should().BeTrue(signed.Message);
        var verified = gpg.Run("--verify", signature, message);
        verified.Ok.Should().BeTrue(verified.All);
    }
}
