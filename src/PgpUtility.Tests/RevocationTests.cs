using PgpUtility.Services;

namespace PgpUtility.Tests;

[Collection(KeyCollection.Name)]
public class RevocationTests
{
    private readonly GeneratedKeys _keys;

    public RevocationTests(GeneratedKeys keys) => _keys = keys;

    [Fact]
    public void Key_generation_produces_a_revocation_certificate()
    {
        _keys.Ed25519.RevocationCertificate.Should().StartWith("-----BEGIN PGP PUBLIC KEY BLOCK-----");
        _keys.Rsa.RevocationCertificate.Should().StartWith("-----BEGIN PGP PUBLIC KEY BLOCK-----");
    }

    [Fact]
    public void A_revocation_certificate_can_be_made_later_from_the_private_key()
    {
        // For anyone whose key predates this app emitting one at creation time.
        string revocation = _keys.Service.CreateRevocationCertificate(
            _keys.Ed25519Private, isFilePath: false, GeneratedKeys.Passphrase());

        revocation.Should().StartWith("-----BEGIN PGP PUBLIC KEY BLOCK-----");
    }

    [Fact]
    public void Making_one_needs_the_right_passphrase()
    {
        // Which is exactly why it is generated up front: if the passphrase is lost, and that is
        // the main reason to revoke, it is already too late to produce one.
        Action act = () => _keys.Service.CreateRevocationCertificate(
            _keys.Ed25519Private, isFilePath: false, "wrong".ToCharArray());

        act.Should().Throw<IncorrectPassphraseException>();
    }

    [SkippableFact]
    public void Gpg_accepts_the_revocation_certificate_and_marks_the_key_revoked()
    {
        Skip.IfNot(GnuPgRunner.IsUsable, "gpg is not usable on this machine");

        // The certificate is only worth anything if other implementations honour it. Asserting on
        // our own parser would prove nothing about what happens when it is actually needed.
        using var work = new TempWorkspace();
        using var gpg = new GnuPgRunner();

        string publicKeyFile = work.Path("pub.asc");
        File.WriteAllText(publicKeyFile, _keys.Ed25519Public);
        gpg.Run("--import", publicKeyFile).All.Should().Contain("imported");

        gpg.Run("--list-keys", "--with-colons").StandardOutput
            .Should().MatchRegex(@"pub:[^r][^\n]*", "the key should not be revoked yet");

        string revocationFile = work.Path("revoke.asc");
        File.WriteAllText(revocationFile, _keys.Ed25519.RevocationCertificate);
        gpg.Run("--import", revocationFile);

        // Field 2 of a pub line is the validity, and "r" is revoked.
        GnuPgRunner.Result listed = gpg.Run("--list-keys", "--with-colons");
        listed.StandardOutput.Should().MatchRegex(@"pub:r:",
            "gpg should treat the key as revoked once the certificate is imported");
    }
}
