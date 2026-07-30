using PgpUtility.Models;
using PgpUtility.Services;

namespace PgpUtility.Tests;

/// <summary>
/// One Ed25519 key pair and one RSA key pair, generated once and shared by every test in the
/// collection.
/// </summary>
/// <remarks>
/// Key generation is the slowest thing in the suite, and RSA is the slowest part of that, so it
/// is done once rather than per test. RSA is 2048 here purely for suite speed; 4096 is the
/// product default and the algorithm path under test is the same either way.
///
/// Keys are generated at run time and never committed. A key pair in the repository would be a
/// published private key, which is exactly what this app exists to help people avoid.
/// </remarks>
public sealed class GeneratedKeys
{
    public const string PassphraseText = "correct horse battery staple";

    /// <summary>
    /// A fresh array on every call. The service clears the copy it is handed, so a shared array
    /// would come back zeroed and every test after the first would fail on the wrong passphrase.
    /// </summary>
    public static char[] Passphrase() => PassphraseText.ToCharArray();

    public IPgpService Service { get; } = new PgpService();

    public string Ed25519Public { get; }
    public string Ed25519Private { get; }
    public string RsaPublic { get; }
    public string RsaPrivate { get; }

    public GeneratedKeys()
    {
        var service = Service;

        (Ed25519Public, Ed25519Private) = service.GenerateKeyPairAsync(new KeyGenerationOptions
        {
            Name = "Ed Tester",
            Email = "ed@example.com",
            Passphrase = Passphrase(),
            Algorithm = PgpKeyAlgorithm.Ed25519
        }).GetAwaiter().GetResult();

        (RsaPublic, RsaPrivate) = service.GenerateKeyPairAsync(new KeyGenerationOptions
        {
            Name = "Rsa Tester",
            Email = "rsa@example.com",
            Passphrase = Passphrase(),
            Algorithm = PgpKeyAlgorithm.Rsa,
            KeySize = 2048
        }).GetAwaiter().GetResult();
    }
}

[CollectionDefinition(Name)]
public sealed class KeyCollection : ICollectionFixture<GeneratedKeys>
{
    public const string Name = "generated keys";
}
