using System.Security.Cryptography;
using PgpUtility.Models;

namespace PgpUtility.Tests;

/// <summary>
/// The failures matter more than the successes. A crypto tool that quietly succeeds on a tampered
/// file is worse than one that does not decrypt at all, because the user acts on the output.
/// </summary>
[Collection(KeyCollection.Name)]
public class FailureModeTests
{
    private readonly GeneratedKeys _keys;

    public FailureModeTests(GeneratedKeys keys) => _keys = keys;

    [Fact]
    public async Task A_wrong_passphrase_fails_with_a_message_naming_the_passphrase()
    {
        using var work = new TempWorkspace();
        string cipher = await EncryptSomething(work);
        string output = work.Path("out.bin");

        OperationResult result = await _keys.Service.DecryptFileAsync(
            cipher, output, _keys.Ed25519Private, isFilePath: false, "wrong passphrase".ToCharArray());

        result.Success.Should().BeFalse();
        result.Message.Should().Contain("passphrase",
            "the user has to be able to tell this apart from a corrupt file");
        File.Exists(output).Should().BeFalse("a failed decrypt must not leave a partial file behind");
    }

    [Fact]
    public async Task An_empty_passphrase_fails_rather_than_being_treated_as_no_passphrase()
    {
        using var work = new TempWorkspace();
        string cipher = await EncryptSomething(work);

        OperationResult result = await _keys.Service.DecryptFileAsync(
            cipher, work.Path("out.bin"), _keys.Ed25519Private, isFilePath: false, Array.Empty<char>());

        result.Success.Should().BeFalse();
    }

    [Fact]
    public async Task The_wrong_key_fails_with_a_message_that_is_not_about_the_passphrase()
    {
        using var work = new TempWorkspace();
        string cipher = await EncryptSomething(work);

        OperationResult result = await _keys.Service.DecryptFileAsync(
            cipher, work.Path("out.bin"), _keys.RsaPrivate, isFilePath: false, GeneratedKeys.Passphrase());

        result.Success.Should().BeFalse();
        result.Message.Should().Contain("not encrypted to the key");
        result.Message.Should().NotContain("Check caps lock",
            "telling someone to retype a correct passphrase sends them round in circles");
    }

    [Theory]
    // Several offsets, because a single flipped byte near one end can land in framing that fails
    // for a different reason than the integrity check.
    [InlineData(0.25)]
    [InlineData(0.50)]
    [InlineData(0.75)]
    public async Task Tampered_ciphertext_is_rejected_and_leaves_no_output(double position)
    {
        using var work = new TempWorkspace();
        string cipher = await EncryptSomething(work, size: 128 * 1024);

        byte[] bytes = File.ReadAllBytes(cipher);
        int index = (int)(bytes.Length * position);
        bytes[index] ^= 0xFF;

        string tampered = work.WriteFile("tampered.pgp", bytes);
        string output = work.Path("tampered.out");

        OperationResult result = await _keys.Service.DecryptFileAsync(
            tampered, output, _keys.Ed25519Private, isFilePath: false, GeneratedKeys.Passphrase());

        result.Success.Should().BeFalse("this is the whole point of the modification detection code");
        File.Exists(output).Should().BeFalse();
        File.Exists(output + ".partial").Should().BeFalse("the staging file must not survive either");
    }

    [Fact]
    public async Task Truncated_ciphertext_is_rejected()
    {
        using var work = new TempWorkspace();
        string cipher = await EncryptSomething(work, size: 128 * 1024);

        byte[] bytes = File.ReadAllBytes(cipher);
        string truncated = work.WriteFile("truncated.pgp", bytes[..(bytes.Length / 2)]);
        string output = work.Path("truncated.out");

        OperationResult result = await _keys.Service.DecryptFileAsync(
            truncated, output, _keys.Ed25519Private, isFilePath: false, GeneratedKeys.Passphrase());

        result.Success.Should().BeFalse();
        File.Exists(output).Should().BeFalse();
    }

    [Fact]
    public async Task A_file_that_is_not_a_pgp_message_fails_cleanly()
    {
        using var work = new TempWorkspace();
        string notPgp = work.WriteFile("notes.txt", "this is just some text"u8.ToArray());

        OperationResult result = await _keys.Service.DecryptFileAsync(
            notPgp, work.Path("out.bin"), _keys.Ed25519Private, isFilePath: false, GeneratedKeys.Passphrase());

        result.Success.Should().BeFalse();
        result.Message.Should().StartWith("Decryption failed:");
    }

    [Fact]
    public async Task Encrypting_to_something_that_is_not_a_key_fails_and_leaves_no_output()
    {
        using var work = new TempWorkspace();
        string plain = work.WriteFile("plain.bin", RandomNumberGenerator.GetBytes(1024));
        string output = work.Path("cipher.pgp");

        OperationResult result = await _keys.Service.EncryptFileAsync(
            plain, output, "not a public key at all", isFilePath: false, armor: false);

        result.Success.Should().BeFalse();
        File.Exists(output).Should().BeFalse();
    }

    private async Task<string> EncryptSomething(TempWorkspace work, int size = 4096)
    {
        string plain = work.WriteFile("plain.bin", RandomNumberGenerator.GetBytes(size));
        string cipher = work.Path("cipher.pgp");
        OperationResult result = await _keys.Service.EncryptFileAsync(
            plain, cipher, _keys.Ed25519Public, isFilePath: false, armor: false);
        result.Success.Should().BeTrue(result.Message);
        return cipher;
    }
}
