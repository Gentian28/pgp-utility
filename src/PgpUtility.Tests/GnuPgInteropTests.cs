using System.Security.Cryptography;
using PgpUtility.Models;
using Xunit;

namespace PgpUtility.Tests;

/// <summary>
/// Interoperability with GnuPG is the claim that matters most and the easiest to get silently
/// wrong. Everything else in this suite tests our code against our code, which would keep passing
/// if we invented our own dialect of OpenPGP.
/// </summary>
/// <remarks>
/// These skip rather than fail where gpg is unavailable or its agent cannot start. A test that
/// could not run and a test that failed are different results and should not look the same. CI
/// runs them on all three platforms, so a skip locally is not a gap in the evidence.
/// </remarks>
[Collection(KeyCollection.Name)]
public class GnuPgInteropTests
{
    private readonly GeneratedKeys _keys;

    public GnuPgInteropTests(GeneratedKeys keys) => _keys = keys;

    [SkippableFact]
    public void Gpg_reads_our_ed25519_key_as_a_signing_key_with_an_encryption_subkey()
    {
        Skip.IfNot(GnuPgRunner.IsUsable, "gpg is not usable on this machine");

        using var work = new TempWorkspace();
        using var gpg = new GnuPgRunner();

        string publicKeyFile = work.Path("pub.asc");
        File.WriteAllText(publicKeyFile, _keys.Ed25519Public);

        GnuPgRunner.Result imported = gpg.Run("--import", publicKeyFile);
        imported.All.Should().Contain("imported");

        GnuPgRunner.Result listed = gpg.Run("--list-keys", "--with-colons");
        listed.Ok.Should().BeTrue(listed.StandardError);

        // Algorithm 22 is EdDSA and 18 is ECDH. Capability "e" on the subkey is what makes the
        // key usable for encryption at all.
        listed.StandardOutput.Should().MatchRegex(@"pub:[^\n]*:22:[^\n]*ed25519");
        listed.StandardOutput.Should().MatchRegex(@"sub:[^\n]*:18:[^\n]*cv25519");
        listed.StandardOutput.Should().Contain("Ed Tester <ed@example.com>");
    }

    [SkippableFact]
    public void Gpg_reads_our_rsa_key()
    {
        Skip.IfNot(GnuPgRunner.IsUsable, "gpg is not usable on this machine");

        using var work = new TempWorkspace();
        using var gpg = new GnuPgRunner();

        string publicKeyFile = work.Path("rsa-pub.asc");
        File.WriteAllText(publicKeyFile, _keys.RsaPublic);

        GnuPgRunner.Result imported = gpg.Run("--import", publicKeyFile);
        imported.All.Should().Contain("imported");
        gpg.Run("--list-keys", "--with-colons").StandardOutput
            .Should().Contain("Rsa Tester <rsa@example.com>");
    }

    [SkippableFact]
    public async Task We_decrypt_what_gpg_encrypted()
    {
        Skip.IfNot(GnuPgRunner.IsUsable, "gpg is not usable on this machine");

        using var work = new TempWorkspace();
        using var gpg = new GnuPgRunner();

        string publicKeyFile = work.Path("pub.asc");
        File.WriteAllText(publicKeyFile, _keys.Ed25519Public);
        gpg.Run("--import", publicKeyFile).All.Should().Contain("imported");

        byte[] original = RandomNumberGenerator.GetBytes(256 * 1024);
        string plain = work.WriteFile("plain.bin", original);
        string cipher = work.Path("from-gpg.pgp");

        GnuPgRunner.Result encrypted = gpg.Run(
            "--trust-model", "always", "--output", cipher,
            "--encrypt", "--recipient", "ed@example.com", plain);
        encrypted.Ok.Should().BeTrue(encrypted.StandardError);

        OperationResult decrypted = await _keys.Service.DecryptFileAsync(
            cipher, work.Path("out.bin"), _keys.Ed25519Private, isFilePath: false, GeneratedKeys.Passphrase());

        decrypted.Success.Should().BeTrue(decrypted.Message);
        File.ReadAllBytes(work.Path("out.bin")).Should().Equal(original);
    }

    [SkippableFact]
    public async Task Gpg_decrypts_what_we_encrypted()
    {
        Skip.IfNot(GnuPgRunner.CanUseSecretKeys, "gpg-agent is not usable on this machine");

        using var work = new TempWorkspace();
        using var gpg = new GnuPgRunner();

        string secretKeyFile = work.Path("sec.asc");
        File.WriteAllText(secretKeyFile, _keys.Ed25519Private);

        // Importing a secret key is what needs the agent, hence the CanUseSecretKeys gate above.
        GnuPgRunner.Result imported = gpg.Run(
            "--pinentry-mode", "loopback", "--passphrase", GeneratedKeys.PassphraseText,
            "--import", secretKeyFile);
        imported.All.Should().Contain("imported");

        byte[] original = RandomNumberGenerator.GetBytes(256 * 1024);
        string plain = work.WriteFile("plain.bin", original);
        string cipher = work.Path("to-gpg.pgp");

        OperationResult encrypted = await _keys.Service.EncryptFileAsync(
            plain, cipher, _keys.Ed25519Public, isFilePath: false, armor: false);
        encrypted.Success.Should().BeTrue(encrypted.Message);

        string output = work.Path("to-gpg.out");
        GnuPgRunner.Result decrypted = gpg.Run(
            "--pinentry-mode", "loopback", "--passphrase", GeneratedKeys.PassphraseText,
            "--output", output, "--decrypt", cipher);

        decrypted.Ok.Should().BeTrue(decrypted.StandardError);
        File.ReadAllBytes(output).Should().Equal(original);
    }

    [SkippableFact]
    public async Task Gpg_decrypts_our_ascii_armored_output()
    {
        Skip.IfNot(GnuPgRunner.CanUseSecretKeys, "gpg-agent is not usable on this machine");

        using var work = new TempWorkspace();
        using var gpg = new GnuPgRunner();

        string secretKeyFile = work.Path("sec.asc");
        File.WriteAllText(secretKeyFile, _keys.Ed25519Private);
        gpg.Run("--pinentry-mode", "loopback", "--passphrase", GeneratedKeys.PassphraseText,
            "--import", secretKeyFile).All.Should().Contain("imported");

        byte[] original = "armored interoperability"u8.ToArray();
        string plain = work.WriteFile("plain.txt", original);
        string cipher = work.Path("armored.asc");

        await _keys.Service.EncryptFileAsync(plain, cipher, _keys.Ed25519Public, isFilePath: false, armor: true);
        File.ReadAllText(cipher).Should().StartWith("-----BEGIN PGP MESSAGE-----");

        string output = work.Path("armored.out");
        GnuPgRunner.Result decrypted = gpg.Run(
            "--pinentry-mode", "loopback", "--passphrase", GeneratedKeys.PassphraseText,
            "--output", output, "--decrypt", cipher);

        decrypted.Ok.Should().BeTrue(decrypted.StandardError);
        File.ReadAllBytes(output).Should().Equal(original);
    }

    [SkippableFact]
    public async Task Our_ciphertext_uses_aes_256_and_carries_an_integrity_packet()
    {
        Skip.IfNot(GnuPgRunner.CanUseSecretKeys, "gpg-agent is not usable on this machine");

        using var work = new TempWorkspace();
        using var gpg = new GnuPgRunner();

        string secretKeyFile = work.Path("sec.asc");
        File.WriteAllText(secretKeyFile, _keys.Ed25519Private);
        gpg.Run("--pinentry-mode", "loopback", "--passphrase", GeneratedKeys.PassphraseText,
            "--import", secretKeyFile).All.Should().Contain("imported");

        string plain = work.WriteFile("plain.bin", RandomNumberGenerator.GetBytes(8192));
        string cipher = work.Path("cipher.pgp");
        await _keys.Service.EncryptFileAsync(plain, cipher, _keys.Ed25519Public, isFilePath: false, armor: false);

        // mdc_method appears only on a tag 18 integrity protected packet, so its presence is gpg
        // confirming the integrity check is really there rather than us asserting our own output.
        //
        // The loopback arguments are not decoration. The secret key is already imported, so
        // --list-packets tries to decrypt the message to list what is inside, and without them
        // the agent raises a pinentry dialog. On a headless runner that prompt fails fast and
        // the assertion below still passes; on a developer's desktop the dialog sits there and
        // the suite hangs until someone cancels it.
        GnuPgRunner.Result packets = gpg.Run(
            "--pinentry-mode", "loopback", "--passphrase", GeneratedKeys.PassphraseText,
            "--list-packets", cipher);
        packets.StandardOutput.Should().Contain("mdc_method");

        // gpg names the session cipher on stderr while decrypting.
        GnuPgRunner.Result decrypted = gpg.Run(
            "--pinentry-mode", "loopback", "--passphrase", GeneratedKeys.PassphraseText,
            "--status-fd", "1", "--output", work.Path("out.bin"), "--decrypt", cipher);

        decrypted.Ok.Should().BeTrue(decrypted.StandardError);
        // DECRYPTION_INFO <mdc_method> <sym_algo>. Symmetric algorithm 9 is AES-256.
        decrypted.All.Should().MatchRegex(@"DECRYPTION_INFO \d+ 9\b");
    }

    [SkippableFact]
    public async Task Gpg_rejects_ciphertext_we_produced_and_then_tampered_with()
    {
        Skip.IfNot(GnuPgRunner.CanUseSecretKeys, "gpg-agent is not usable on this machine");

        // Confirms the integrity check is a real OpenPGP one rather than something only our own
        // decrypt path knows how to verify.
        using var work = new TempWorkspace();
        using var gpg = new GnuPgRunner();

        string secretKeyFile = work.Path("sec.asc");
        File.WriteAllText(secretKeyFile, _keys.Ed25519Private);
        gpg.Run("--pinentry-mode", "loopback", "--passphrase", GeneratedKeys.PassphraseText,
            "--import", secretKeyFile).All.Should().Contain("imported");

        string plain = work.WriteFile("plain.bin", RandomNumberGenerator.GetBytes(64 * 1024));
        string cipher = work.Path("cipher.pgp");
        await _keys.Service.EncryptFileAsync(plain, cipher, _keys.Ed25519Public, isFilePath: false, armor: false);

        byte[] bytes = File.ReadAllBytes(cipher);
        bytes[bytes.Length / 2] ^= 0xFF;
        string tampered = work.WriteFile("tampered.pgp", bytes);

        GnuPgRunner.Result decrypted = gpg.Run(
            "--pinentry-mode", "loopback", "--passphrase", GeneratedKeys.PassphraseText,
            "--output", work.Path("tampered.out"), "--decrypt", tampered);

        decrypted.Ok.Should().BeFalse("gpg must reject a message whose integrity check does not match");
    }
}
