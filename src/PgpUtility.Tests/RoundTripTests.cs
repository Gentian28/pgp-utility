using System.Security.Cryptography;
using PgpUtility.Models;

namespace PgpUtility.Tests;

[Collection(KeyCollection.Name)]
public class RoundTripTests
{
    private readonly GeneratedKeys _keys;

    public RoundTripTests(GeneratedKeys keys) => _keys = keys;

    public static TheoryData<string, bool> Variants() => new()
    {
        { "ed25519", false },
        { "ed25519", true },
        { "rsa", false },
        { "rsa", true },
    };

    [Theory]
    [MemberData(nameof(Variants))]
    public async Task Generate_encrypt_decrypt_returns_the_original_bytes(string algorithm, bool armor)
    {
        using var work = new TempWorkspace();
        (string publicKey, string privateKey) = Select(algorithm);

        byte[] original = RandomNumberGenerator.GetBytes(512 * 1024);
        string plain = work.WriteFile("plain.bin", original);
        string cipher = work.Path("cipher.pgp");
        string output = work.Path("decrypted.bin");

        OperationResult encrypted = await _keys.Service.EncryptFileAsync(
            plain, cipher, publicKey, isFilePath: false, armor);
        encrypted.Success.Should().BeTrue(encrypted.Message);

        OperationResult decrypted = await _keys.Service.DecryptFileAsync(
            cipher, output, privateKey, isFilePath: false, GeneratedKeys.Passphrase());
        decrypted.Success.Should().BeTrue(decrypted.Message);

        File.ReadAllBytes(output).Should().Equal(original);
    }

    [Theory]
    [MemberData(nameof(Variants))]
    public async Task A_verified_message_reports_no_integrity_warning(string algorithm, bool armor)
    {
        using var work = new TempWorkspace();
        (string publicKey, string privateKey) = Select(algorithm);

        string plain = work.WriteFile("plain.bin", RandomNumberGenerator.GetBytes(4096));
        string cipher = work.Path("cipher.pgp");

        await _keys.Service.EncryptFileAsync(plain, cipher, publicKey, isFilePath: false, armor);
        OperationResult decrypted = await _keys.Service.DecryptFileAsync(
            cipher, work.Path("out.bin"), privateKey, isFilePath: false, GeneratedKeys.Passphrase());

        decrypted.Success.Should().BeTrue(decrypted.Message);
        decrypted.Warning.Should().BeNull("the message we produced is integrity protected");
    }

    [Fact]
    public async Task An_empty_file_round_trips()
    {
        using var work = new TempWorkspace();

        string plain = work.WriteFile("empty.bin", Array.Empty<byte>());
        string cipher = work.Path("empty.pgp");
        string output = work.Path("empty.out");

        await _keys.Service.EncryptFileAsync(plain, cipher, _keys.Ed25519Public, isFilePath: false, armor: false);
        OperationResult decrypted = await _keys.Service.DecryptFileAsync(
            cipher, output, _keys.Ed25519Private, isFilePath: false, GeneratedKeys.Passphrase());

        decrypted.Success.Should().BeTrue(decrypted.Message);
        new FileInfo(output).Length.Should().Be(0);
    }

    [Fact]
    public async Task Encrypting_the_same_bytes_twice_produces_different_ciphertext()
    {
        // A fresh session key and IV every time. Identical output would mean one of them is being
        // reused, which leaks that two files are the same without decrypting either.
        using var work = new TempWorkspace();
        string plain = work.WriteFile("plain.bin", RandomNumberGenerator.GetBytes(4096));

        await _keys.Service.EncryptFileAsync(plain, work.Path("a.pgp"), _keys.Ed25519Public, isFilePath: false, armor: false);
        await _keys.Service.EncryptFileAsync(plain, work.Path("b.pgp"), _keys.Ed25519Public, isFilePath: false, armor: false);

        File.ReadAllBytes(work.Path("a.pgp")).Should().NotEqual(File.ReadAllBytes(work.Path("b.pgp")));
    }

    [Fact]
    public async Task Keys_read_from_a_file_work_the_same_as_keys_read_from_a_string()
    {
        using var work = new TempWorkspace();

        string publicKeyFile = work.Path("pub.asc");
        string privateKeyFile = work.Path("sec.asc");
        await File.WriteAllTextAsync(publicKeyFile, _keys.Ed25519Public);
        await File.WriteAllTextAsync(privateKeyFile, _keys.Ed25519Private);

        byte[] original = RandomNumberGenerator.GetBytes(8192);
        string plain = work.WriteFile("plain.bin", original);

        await _keys.Service.EncryptFileAsync(
            plain, work.Path("c.pgp"), publicKeyFile, isFilePath: true, armor: false);
        OperationResult decrypted = await _keys.Service.DecryptFileAsync(
            work.Path("c.pgp"), work.Path("out.bin"), privateKeyFile, isFilePath: true, GeneratedKeys.Passphrase());

        decrypted.Success.Should().BeTrue(decrypted.Message);
        File.ReadAllBytes(work.Path("out.bin")).Should().Equal(original);
    }

    private (string Public, string Private) Select(string algorithm) => algorithm switch
    {
        "ed25519" => (_keys.Ed25519Public, _keys.Ed25519Private),
        "rsa" => (_keys.RsaPublic, _keys.RsaPrivate),
        _ => throw new ArgumentOutOfRangeException(nameof(algorithm))
    };
}
