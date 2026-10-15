using System.Text;
using Org.BouncyCastle.Bcpg;
using Org.BouncyCastle.Bcpg.OpenPgp;
using PgpUtility.Models;
using PgpUtility.Services;

namespace PgpUtility.Tests;

[Collection(KeyCollection.Name)]
public class SafetyRegressionTests(GeneratedKeys keys)
{
    [Fact]
    public async Task A_subkey_from_another_identity_cannot_receive_ciphertext_under_the_expected_fingerprint()
    {
        var alice = Read(keys.Ed25519Public);
        var bob = await keys.Service.GenerateKeyPairAsync(new() { Name = "Synthetic Bob", Passphrase = GeneratedKeys.Passphrase() });
        var swapped = Encode(new[] { alice.GetPublicKey(), Read(bob.PublicKey).GetPublicKeys().First(k => !k.IsMasterKey) });
        var result = await keys.Service.EncryptTextAsync("Only Alice may read this", swapped, false);
        result.Success.Should().BeFalse();
        result.Payload.Should().BeNull();
        Action inspect = () => keys.Service.ReadPublicKeyInfo(swapped, false);
        inspect.Should().Throw<PgpException>();
    }

    [Fact]
    public async Task A_user_id_without_its_own_self_certification_cannot_be_reported_as_the_signer()
    {
        var ring = Read(keys.Ed25519Public);
        var master = ring.GetPublicKey();
        string id = master.GetUserIds().First();
        var certification = master.GetSignaturesForId(id).First();
        var changed = PgpPublicKey.RemoveCertification(master, id);
        changed = PgpPublicKey.AddCertification(changed, "Forged identity", certification);
        var forged = Encode(new[] { changed }.Concat(ring.GetPublicKeys().Where(k => !k.IsMasterKey)));
        var signed = await keys.Signatures.SignTextAsync("hello", keys.Ed25519Private, false, GeneratedKeys.Passphrase());
        var result = await keys.Signatures.VerifyTextAsync(signed.Payload!, forged, false);
        result.IsValid.Should().BeFalse();
        result.SignerUserId.Should().BeNull();
    }

    [Fact]
    public async Task Unrelated_rings_in_one_file_cannot_bypass_the_expected_identity()
    {
        string bundled;
        using (var buffer = new MemoryStream())
        {
            using (var armor = new ArmoredOutputStream(buffer))
            {
                Read(keys.Ed25519Public).Encode(armor);
                Read(keys.RsaPublic).Encode(armor);
            }
            bundled = Encoding.UTF8.GetString(buffer.ToArray());
        }
        var result = await keys.Service.EncryptTextAsync("secret", bundled, false);
        result.Success.Should().BeFalse();
    }

    [Fact]
    public async Task A_revoked_primary_blocks_new_encryption_but_not_old_decryption()
    {
        var before = await keys.Service.EncryptTextAsync("old ciphertext", keys.Ed25519Public, false);
        var ring = Read(keys.Ed25519Public);
        var signatures = (PgpSignatureList)new PgpObjectFactory(PgpUtilities.GetDecoderStream(
            new MemoryStream(Encoding.UTF8.GetBytes(keys.Ed25519.RevocationCertificate)))).NextPgpObject();
        var revoked = PgpPublicKey.AddCertification(ring.GetPublicKey(), signatures[0]);
        string publicKey = Encode(new[] { revoked }.Concat(ring.GetPublicKeys().Where(k => !k.IsMasterKey)));
        var result = await keys.Service.EncryptTextAsync("new ciphertext", publicKey, false);
        result.Success.Should().BeFalse();
        var old = await keys.Service.DecryptTextAsync(before.Payload!, keys.Ed25519Private, false, GeneratedKeys.Passphrase());
        old.Payload.Should().Be("old ciphertext");
    }

    [Theory]
    [InlineData("encrypt")]
    [InlineData("decrypt")]
    [InlineData("sign")]
    public async Task A_failed_operation_preserves_an_existing_destination(string operation)
    {
        using var work = new TempWorkspace();
        string input = work.WriteFile("input", "original bytes"u8.ToArray());
        string output = work.WriteFile("output", "existing bytes"u8.ToArray());
        var result = operation switch
        {
            "encrypt" => await keys.Service.EncryptFileAsync(input, output, "invalid", false, false),
            "decrypt" => await keys.Service.DecryptFileAsync(input, output, keys.Ed25519Private, false, "wrong".ToCharArray()),
            _ => await keys.Signatures.SignFileAsync(input, output, keys.Ed25519Private, false, "wrong".ToCharArray(), true)
        };
        result.Success.Should().BeFalse();
        File.ReadAllText(input).Should().Be("original bytes");
        File.ReadAllText(output).Should().Be("existing bytes");
        Directory.GetFiles(work.Root, ".pgputility-*.partial").Should().BeEmpty();
    }

    [Fact]
    public async Task Encrypting_in_place_is_rejected_without_touching_the_source()
    {
        using var work = new TempWorkspace();
        string input = work.WriteFile("input", "original"u8.ToArray());
        var result = await keys.Service.EncryptFileAsync(input, input, keys.Ed25519Public, false, false);
        result.Success.Should().BeFalse();
        File.ReadAllText(input).Should().Be("original");
    }

    [Fact]
    public async Task Cancellation_after_work_starts_does_not_publish_an_encrypted_file()
    {
        using var work = new TempWorkspace();
        using var cancellation = new CancellationTokenSource();
        string input = work.WriteFile("input", new byte[1024 * 1024]);
        string output = work.Path("output");
        var result = await keys.Service.EncryptFileAsync(input, output, keys.Ed25519Public, false, false,
            new ImmediateProgress(_ => cancellation.Cancel()), cancellation.Token);
        result.IsCanceled.Should().BeTrue();
        File.Exists(output).Should().BeFalse();
        Directory.GetFiles(work.Root, ".pgputility-*.partial").Should().BeEmpty();
    }

    [Theory]
    [InlineData("Unicode NBSP\u00a0")]
    [InlineData("Unicode EM SPACE\u2003")]
    [InlineData("CR only\rnext line")]
    [InlineData("- dash escaped\n\nfinal line\n")]
    public async Task Canonical_text_signatures_preserve_meaningful_unicode_and_line_boundaries(string text)
    {
        var signed = await keys.Signatures.SignTextAsync(text, keys.Ed25519Private, false, GeneratedKeys.Passphrase());
        var verified = await keys.Signatures.VerifyTextAsync(signed.Payload!, keys.Ed25519Public, false);
        verified.IsValid.Should().BeTrue(verified.Message);
    }

    [Fact]
    public async Task A_past_expiry_is_rejected_instead_of_becoming_a_permanent_key()
    {
        Func<Task> generate = async () => await keys.Service.GenerateKeyPairAsync(new()
        { Name = "Past expiry", Passphrase = GeneratedKeys.Passphrase(), ExpirationDate = DateTime.UtcNow.AddDays(-1) });
        await generate.Should().ThrowAsync<ArgumentException>();
    }

    [Fact]
    public async Task A_destination_created_during_work_is_preserved_at_commit()
    {
        using var work = new TempWorkspace();
        string destination = work.Path("output");
        using var transaction = new FileTransaction(destination);
        transaction.Stream.Write("new"u8);
        await File.WriteAllTextAsync(destination, "other operation");
        Action commit = () => transaction.Commit();
        commit.Should().Throw<IOException>();
        File.ReadAllText(destination).Should().Be("other operation");
    }

    [Fact]
    public void A_batch_reserves_distinct_names_and_preserves_all_input_paths()
    {
        using var work = new TempWorkspace();
        Directory.CreateDirectory(work.Path("one"));
        Directory.CreateDirectory(work.Path("two"));
        string one = work.WriteFile("one/report.txt", "one"u8.ToArray());
        string two = work.WriteFile("two/report.txt", "two"u8.ToArray());
        work.WriteFile("report.txt.asc", "existing"u8.ToArray());
        var plan = BatchOutputPlan.Create(new[] { one, two }, work.Root, true, true);
        plan.Select(p => p.OutputPath).Distinct().Should().HaveCount(2);
        plan.Should().OnlyContain(p => !File.Exists(p.OutputPath));
        File.ReadAllText(work.Path("report.txt.asc")).Should().Be("existing");
    }

    [Fact]
    public void A_superseded_request_cannot_publish_its_verdict()
    {
        var revision = new OperationRevision();
        int checking = revision.Next();
        revision.Next();
        revision.IsCurrent(checking).Should().BeFalse();
    }

    internal static PgpPublicKeyRing Read(string text) => new(PgpUtilities.GetDecoderStream(new MemoryStream(Encoding.UTF8.GetBytes(text))));
    internal static string Encode(IEnumerable<PgpPublicKey> packets)
    {
        using var stream = new MemoryStream();
        using (var armor = new ArmoredOutputStream(stream)) foreach (var packet in packets) packet.Encode(armor);
        return Encoding.UTF8.GetString(stream.ToArray());
    }
    private sealed class ImmediateProgress(Action<string> report) : IProgress<string> { public void Report(string value) => report(value); }
}
