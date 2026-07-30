using System.Security.Cryptography;
using PgpUtility.Models;

namespace PgpUtility.Tests;

/// <summary>
/// Streaming buffers are where file tools break. Small fixtures fit in one buffer and never
/// exercise the loop, so a size well past every buffer boundary is the only thing that proves the
/// streaming path.
/// </summary>
[Collection(KeyCollection.Name)]
public class LargeFileTests
{
    private const long Size = 128L * 1024 * 1024;

    private readonly GeneratedKeys _keys;

    public LargeFileTests(GeneratedKeys keys) => _keys = keys;

    [Fact]
    public async Task A_128_MB_file_round_trips_and_hashes_the_same()
    {
        using var work = new TempWorkspace();
        string plain = work.Path("large.bin");

        // Written in chunks and compared by hash rather than by loading both files into memory.
        // Two 128 MB byte arrays plus the assertion machinery is a needless way to fail on a CI
        // runner, and it would be measuring the test rather than the code.
        byte[] expectedHash = WriteRandomFile(plain, Size);

        string cipher = work.Path("large.pgp");
        string output = work.Path("large.out");

        OperationResult encrypted = await _keys.Service.EncryptFileAsync(
            plain, cipher, _keys.Ed25519Public, isFilePath: false, armor: false);
        encrypted.Success.Should().BeTrue(encrypted.Message);

        OperationResult decrypted = await _keys.Service.DecryptFileAsync(
            cipher, output, _keys.Ed25519Private, isFilePath: false, GeneratedKeys.Passphrase());
        decrypted.Success.Should().BeTrue(decrypted.Message);

        new FileInfo(output).Length.Should().Be(Size);
        HashFile(output).Should().Equal(expectedHash);
    }

    private static byte[] WriteRandomFile(string path, long size)
    {
        using var sha = SHA256.Create();
        using var stream = File.Create(path);

        // Random data so compression cannot hide a bug by shrinking the payload below a buffer
        // boundary. A file of zeroes would compress to almost nothing and prove nothing.
        var chunk = new byte[1024 * 1024];
        long written = 0;
        while (written < size)
        {
            int count = (int)Math.Min(chunk.Length, size - written);
            RandomNumberGenerator.Fill(chunk.AsSpan(0, count));
            stream.Write(chunk, 0, count);
            sha.TransformBlock(chunk, 0, count, null, 0);
            written += count;
        }

        sha.TransformFinalBlock(Array.Empty<byte>(), 0, 0);
        return sha.Hash!;
    }

    private static byte[] HashFile(string path)
    {
        using var sha = SHA256.Create();
        using var stream = File.OpenRead(path);
        return sha.ComputeHash(stream);
    }
}
