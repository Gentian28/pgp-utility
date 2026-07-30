using System.Security.Cryptography;
using PgpUtility.Models;

namespace PgpUtility.Tests;

[Collection(KeyCollection.Name)]
public class SignatureTests
{
    private readonly GeneratedKeys _keys;

    public SignatureTests(GeneratedKeys keys) => _keys = keys;

    public static TheoryData<string, bool> Variants() => new()
    {
        { "ed25519", false },
        { "ed25519", true },
        { "rsa", false },
        { "rsa", true },
    };

    [Theory]
    [MemberData(nameof(Variants))]
    public async Task A_signature_verifies_against_the_file_it_was_made_for(string algorithm, bool armor)
    {
        using var work = new TempWorkspace();
        (string publicKey, string privateKey) = Select(algorithm);

        string file = work.WriteFile("payload.bin", RandomNumberGenerator.GetBytes(64 * 1024));
        string signature = work.Path("payload.sig");

        OperationResult signed = await _keys.Signatures.SignFileAsync(
            file, signature, privateKey, isFilePath: false, GeneratedKeys.Passphrase(), armor);
        signed.Success.Should().BeTrue(signed.Message);

        SignatureVerification verified = await _keys.Signatures.VerifyFileAsync(
            file, signature, publicKey, isFilePath: false);

        verified.Completed.Should().BeTrue(verified.Message);
        verified.IsValid.Should().BeTrue(verified.Message);
        verified.Caveat.Should().BeNull();
    }

    [Fact]
    public async Task Signing_leaves_the_original_file_untouched()
    {
        // The point of a detached signature: a recipient without this tool can still open the file.
        using var work = new TempWorkspace();
        byte[] original = RandomNumberGenerator.GetBytes(4096);
        string file = work.WriteFile("payload.bin", original);

        await _keys.Signatures.SignFileAsync(
            file, work.Path("payload.sig"), _keys.Ed25519Private, isFilePath: false,
            GeneratedKeys.Passphrase(), armor: true);

        File.ReadAllBytes(file).Should().Equal(original);
    }

    [Fact]
    public async Task A_modified_file_fails_verification()
    {
        using var work = new TempWorkspace();
        string file = work.WriteFile("payload.bin", RandomNumberGenerator.GetBytes(8192));
        string signature = work.Path("payload.sig");

        await _keys.Signatures.SignFileAsync(
            file, signature, _keys.Ed25519Private, isFilePath: false, GeneratedKeys.Passphrase(), armor: true);

        byte[] bytes = File.ReadAllBytes(file);
        bytes[100] ^= 0x01;
        File.WriteAllBytes(file, bytes);

        SignatureVerification verified = await _keys.Signatures.VerifyFileAsync(
            file, signature, _keys.Ed25519Public, isFilePath: false);

        verified.Completed.Should().BeTrue();
        verified.IsValid.Should().BeFalse("one flipped bit must break the signature");
    }

    [Fact]
    public async Task A_signature_from_a_different_key_is_reported_as_the_wrong_key()
    {
        using var work = new TempWorkspace();
        string file = work.WriteFile("payload.bin", RandomNumberGenerator.GetBytes(4096));
        string signature = work.Path("payload.sig");

        await _keys.Signatures.SignFileAsync(
            file, signature, _keys.Ed25519Private, isFilePath: false, GeneratedKeys.Passphrase(), armor: true);

        SignatureVerification verified = await _keys.Signatures.VerifyFileAsync(
            file, signature, _keys.RsaPublic, isFilePath: false);

        verified.IsValid.Should().BeFalse();
        verified.Message.Should().Contain("not the key you selected");
    }

    [Fact]
    public async Task Signing_with_the_wrong_passphrase_fails_and_writes_no_signature()
    {
        using var work = new TempWorkspace();
        string file = work.WriteFile("payload.bin", RandomNumberGenerator.GetBytes(1024));
        string signature = work.Path("payload.sig");

        OperationResult signed = await _keys.Signatures.SignFileAsync(
            file, signature, _keys.Ed25519Private, isFilePath: false,
            "wrong".ToCharArray(), armor: true);

        signed.Success.Should().BeFalse();
        signed.Message.Should().Contain("passphrase");
        File.Exists(signature).Should().BeFalse();
    }

    [Fact]
    public async Task Verifying_against_something_that_is_not_a_signature_fails_cleanly()
    {
        using var work = new TempWorkspace();
        string file = work.WriteFile("payload.bin", RandomNumberGenerator.GetBytes(1024));
        string notASignature = work.WriteFile("notes.txt", "just some text"u8.ToArray());

        SignatureVerification verified = await _keys.Signatures.VerifyFileAsync(
            file, notASignature, _keys.Ed25519Public, isFilePath: false);

        verified.IsValid.Should().BeFalse();
        verified.Completed.Should().BeFalse("nothing was checked, so this is not a verdict");
    }

    [Fact]
    public async Task The_signer_identity_is_reported()
    {
        using var work = new TempWorkspace();
        string file = work.WriteFile("payload.bin", RandomNumberGenerator.GetBytes(1024));
        string signature = work.Path("payload.sig");

        await _keys.Signatures.SignFileAsync(
            file, signature, _keys.Ed25519Private, isFilePath: false, GeneratedKeys.Passphrase(), armor: true);

        SignatureVerification verified = await _keys.Signatures.VerifyFileAsync(
            file, signature, _keys.Ed25519Public, isFilePath: false);

        verified.SignerUserId.Should().Be("Ed Tester <ed@example.com>");
        verified.SignerKeyId.Should().MatchRegex("^0x[0-9A-F]{16}$");
        verified.SignedAt.Should().BeCloseTo(DateTime.UtcNow, TimeSpan.FromMinutes(5));
    }

    // --- Clear-signed text ---

    [Theory]
    [InlineData("A short message.")]
    [InlineData("Line one\nLine two\nLine three")]
    [InlineData("Trailing spaces are stripped when signing   \nso this must still verify")]
    [InlineData("Unicode survives: naïve café 日本語 emoji 🔐")]
    public async Task Clear_signed_text_verifies(string message)
    {
        OperationResult signed = await _keys.Signatures.SignTextAsync(
            message, _keys.Ed25519Private, isFilePath: false, GeneratedKeys.Passphrase());

        signed.Success.Should().BeTrue(signed.Message);
        signed.Payload.Should().StartWith("-----BEGIN PGP SIGNED MESSAGE-----");

        SignatureVerification verified = await _keys.Signatures.VerifyTextAsync(
            signed.Payload!, _keys.Ed25519Public, isFilePath: false);

        verified.IsValid.Should().BeTrue(verified.Message);
    }

    [Fact]
    public async Task Tampered_clear_signed_text_fails_verification()
    {
        OperationResult signed = await _keys.Signatures.SignTextAsync(
            "Transfer 100 to Alice", _keys.Ed25519Private, isFilePath: false, GeneratedKeys.Passphrase());

        // The whole point of signing a message: changing what it says has to break the signature.
        string tampered = signed.Payload!.Replace("Transfer 100 to Alice", "Transfer 900 to Mallory");

        SignatureVerification verified = await _keys.Signatures.VerifyTextAsync(
            tampered, _keys.Ed25519Public, isFilePath: false);

        verified.IsValid.Should().BeFalse();
    }

    private (string Public, string Private) Select(string algorithm) => algorithm switch
    {
        "ed25519" => (_keys.Ed25519Public, _keys.Ed25519Private),
        "rsa" => (_keys.RsaPublic, _keys.RsaPrivate),
        _ => throw new ArgumentOutOfRangeException(nameof(algorithm))
    };
}
