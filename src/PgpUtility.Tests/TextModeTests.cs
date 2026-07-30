using PgpUtility.Models;

namespace PgpUtility.Tests;

[Collection(KeyCollection.Name)]
public class TextModeTests
{
    private readonly GeneratedKeys _keys;

    public TextModeTests(GeneratedKeys keys) => _keys = keys;

    [Theory]
    [InlineData("hello")]
    [InlineData("")]
    [InlineData("multi\nline\ntext")]
    [InlineData("Unicode: naïve café 日本語 emoji 🔐")]
    [InlineData("Windows line endings\r\nand a second line")]
    public async Task Text_round_trips_exactly(string original)
    {
        OperationResult encrypted = await _keys.Service.EncryptTextAsync(
            original, _keys.Ed25519Public, isFilePath: false);
        encrypted.Success.Should().BeTrue(encrypted.Message);
        encrypted.Payload.Should().StartWith("-----BEGIN PGP MESSAGE-----");

        OperationResult decrypted = await _keys.Service.DecryptTextAsync(
            encrypted.Payload!, _keys.Ed25519Private, isFilePath: false, GeneratedKeys.Passphrase());

        decrypted.Success.Should().BeTrue(decrypted.Message);
        decrypted.Payload.Should().Be(original);
    }

    [Fact]
    public async Task Encrypted_text_is_always_armored_so_it_can_be_pasted()
    {
        OperationResult encrypted = await _keys.Service.EncryptTextAsync(
            "paste me", _keys.Ed25519Public, isFilePath: false);

        encrypted.Payload.Should().StartWith("-----BEGIN PGP MESSAGE-----");
        encrypted.Payload.Should().Contain("-----END PGP MESSAGE-----");
    }

    [Fact]
    public async Task A_wrong_passphrase_fails_with_an_actionable_message()
    {
        OperationResult encrypted = await _keys.Service.EncryptTextAsync(
            "secret", _keys.Ed25519Public, isFilePath: false);

        OperationResult decrypted = await _keys.Service.DecryptTextAsync(
            encrypted.Payload!, _keys.Ed25519Private, isFilePath: false, "wrong".ToCharArray());

        decrypted.Success.Should().BeFalse();
        decrypted.Message.Should().Contain("passphrase");
    }

    [Fact]
    public async Task Tampered_text_is_rejected_and_yields_no_payload()
    {
        OperationResult encrypted = await _keys.Service.EncryptTextAsync(
            new string('x', 4000), _keys.Ed25519Public, isFilePath: false);

        // Corrupt a character in the middle of the base64 body, past the armor header.
        string armored = encrypted.Payload!;
        int middle = armored.Length / 2;
        char replacement = armored[middle] == 'A' ? 'B' : 'A';
        string tampered = armored[..middle] + replacement + armored[(middle + 1)..];

        OperationResult decrypted = await _keys.Service.DecryptTextAsync(
            tampered, _keys.Ed25519Private, isFilePath: false, GeneratedKeys.Passphrase());

        decrypted.Success.Should().BeFalse();
        decrypted.Payload.Should().BeNull("unverified plaintext must never reach the caller");
    }

    [Fact]
    public async Task Text_that_is_not_a_pgp_message_fails_cleanly()
    {
        OperationResult decrypted = await _keys.Service.DecryptTextAsync(
            "just some text someone pasted", _keys.Ed25519Private, isFilePath: false, GeneratedKeys.Passphrase());

        decrypted.Success.Should().BeFalse();
        decrypted.Message.Should().StartWith("Decryption failed:");
    }

    [Fact]
    public async Task Text_mode_and_file_mode_produce_interchangeable_messages()
    {
        // They share one core on purpose. If they ever diverge, a message encrypted in one tab
        // would stop opening in the other, which is the kind of thing nobody notices until a user
        // reports it.
        using var work = new TempWorkspace();

        OperationResult encrypted = await _keys.Service.EncryptTextAsync(
            "written as text, read as a file", _keys.Ed25519Public, isFilePath: false);

        string asFile = work.Path("message.asc");
        await File.WriteAllTextAsync(asFile, encrypted.Payload!);

        OperationResult decrypted = await _keys.Service.DecryptFileAsync(
            asFile, work.Path("message.txt"), _keys.Ed25519Private, isFilePath: false, GeneratedKeys.Passphrase());

        decrypted.Success.Should().BeTrue(decrypted.Message);
        (await File.ReadAllTextAsync(work.Path("message.txt")))
            .Should().Be("written as text, read as a file");
    }
}
