using System.IO.Compression;
using System.Text;
using System.Text.Json;
using PgpUtility.Services;

namespace PgpUtility.Tests;

[Collection(KeyCollection.Name)]
public class BackupAndLifecycleTests(GeneratedKeys keys)
{
    [SkippableFact]
    public async Task Gpg_accepts_renewal_and_the_changed_utf8_private_key_passphrase()
    {
        Skip.IfNot(GnuPgRunner.CanUseSecretKeys, "gpg-agent is not usable");
        using var work = new TempWorkspace();
        var store = new KeyStoreService(keys.Service, work.Path("store"));
        var key = await store.ImportKeyFromStringAsync(keys.Ed25519Private, true);
        DateTime expiry = DateTime.UtcNow.AddYears(4);
        await store.ExtendExpiryAsync(key.Fingerprint, expiry, GeneratedKeys.Passphrase());
        const string next = "synthetic caf\u00e9 next";
        await store.ChangePassphraseAsync(key.Fingerprint, GeneratedKeys.Passphrase(), next.ToCharArray());
        using var gpg = new GnuPgRunner();
        var imported = gpg.Run("--pinentry-mode", "loopback", "--passphrase", next, "--import", store.GetKeyFilePath(key.Fingerprint, true)!);
        imported.Ok.Should().BeTrue(imported.All);
        var listing = gpg.Run("--with-colons", "--list-keys").StandardOutput;
        long expected = new DateTimeOffset(expiry).ToUnixTimeSeconds();
        foreach (string line in listing.Split('\n').Where(l => l.StartsWith("pub:", StringComparison.Ordinal) || l.StartsWith("sub:", StringComparison.Ordinal)))
            long.Parse(line.Split(':')[6], System.Globalization.CultureInfo.InvariantCulture).Should().BeInRange(expected - 1, expected + 1);
        var message = await keys.Service.EncryptTextAsync("old identity still works", store.GetKeyFilePath(key.Fingerprint, false)!, true);
        string encrypted = work.WriteFile("encrypted.asc", System.Text.Encoding.UTF8.GetBytes(message.Payload!));
        string output = work.Path("plaintext.txt");
        var decrypted = gpg.Run("--pinentry-mode", "loopback", "--passphrase", next, "--output", output, "--decrypt", encrypted);
        decrypted.Ok.Should().BeTrue(decrypted.All);
        File.ReadAllText(output).Should().Be("old identity still works");
    }

    [Fact]
    public async Task Backup_restore_keeps_private_access_and_revocation_material()
    {
        using var work = new TempWorkspace();
        var source = new KeyStoreService(keys.Service, work.Path("source"));
        var key = await source.ImportKeyFromStringAsync(keys.Ed25519Private, true);
        await source.SaveRevocationCertificateAsync(key.Fingerprint, keys.Ed25519.RevocationCertificate);
        string backup = work.Path("backup.zip");
        await source.ExportBackupAsync(backup);
        var target = new KeyStoreService(keys.Service, work.Path("target"));
        (await target.RestoreBackupAsync(backup)).Should().Be(1);
        var encrypted = await keys.Service.EncryptTextAsync("before backup", keys.Ed25519Public, false);
        var decrypted = await keys.Service.DecryptTextAsync(encrypted.Payload!, target.GetKeyFilePath(key.Fingerprint, true)!, true, GeneratedKeys.Passphrase());
        decrypted.Payload.Should().Be("before backup");
        string certificate = work.Path("restored-revocation.asc");
        await target.ExportRevocationCertificateAsync(key.Fingerprint, certificate, []);
        File.ReadAllText(certificate).Should().Be(keys.Ed25519.RevocationCertificate);
    }

    [Fact]
    public async Task A_backup_with_path_traversal_is_rejected_before_any_store_change()
    {
        using var work = new TempWorkspace();
        string archivePath = work.Path("malicious.zip");
        using (var archive = ZipFile.Open(archivePath, ZipArchiveMode.Create))
        using (var output = archive.CreateEntry("../escape.asc").Open()) output.Write("not a key"u8);
        var store = new KeyStoreService(keys.Service, work.Path("keys"));
        Func<Task> restore = () => store.RestoreBackupAsync(archivePath);
        await restore.Should().ThrowAsync<InvalidDataException>();
        store.GetAllKeys().Should().BeEmpty();
        File.Exists(work.Path("escape.asc")).Should().BeFalse();
    }

    [Fact]
    public async Task A_bad_key_in_a_backup_cannot_cause_a_partial_restore()
    {
        using var work = new TempWorkspace();
        var store = new KeyStoreService(keys.Service, work.Path("source"));
        var key = await store.ImportKeyFromStringAsync(keys.Ed25519Private, true);
        string backup = work.Path("backup.zip");
        await store.ExportBackupAsync(backup);
        using (var archive = ZipFile.Open(backup, ZipArchiveMode.Update))
        {
            archive.GetEntry("sec_" + key.Fingerprint + ".asc")!.Delete();
            using var writer = new StreamWriter(archive.CreateEntry("sec_" + key.Fingerprint + ".asc").Open());
            writer.Write("not a key");
        }
        var target = new KeyStoreService(keys.Service, work.Path("target"));
        Func<Task> restore = () => target.RestoreBackupAsync(backup);
        await restore.Should().ThrowAsync<Exception>();
        target.GetAllKeys().Should().BeEmpty();
    }

    [Fact]
    public async Task Changing_a_unicode_passphrase_preserves_identity_and_old_message_access()
    {
        using var work = new TempWorkspace();
        var store = new KeyStoreService(keys.Service, work.Path("keys"));
        var key = await store.ImportKeyFromStringAsync(keys.Ed25519Private, true);
        var encrypted = await keys.Service.EncryptTextAsync("old message", keys.Ed25519Public, false);
        char[] next = "synthetic caf\u00e9 passphrase".ToCharArray();
        await store.ChangePassphraseAsync(key.Fingerprint, GeneratedKeys.Passphrase(), next);
        string path = store.GetKeyFilePath(key.Fingerprint, true)!;
        var decrypted = await keys.Service.DecryptTextAsync(encrypted.Payload!, path, true, next);
        decrypted.Payload.Should().Be("old message");
        var old = await keys.Service.DecryptTextAsync(encrypted.Payload!, path, true, GeneratedKeys.Passphrase());
        old.Success.Should().BeFalse();
        store.GetAllKeys().Single().Fingerprint.Should().Be(key.Fingerprint);
        Array.Clear(next);
    }

    [Fact]
    public async Task Renewal_updates_primary_and_encryption_subkey_expiry_without_changing_the_fingerprint()
    {
        using var work = new TempWorkspace();
        var store = new KeyStoreService(keys.Service, work.Path("keys"));
        var key = await store.ImportKeyFromStringAsync(keys.Ed25519Private, true);
        DateTime expiry = DateTime.UtcNow.AddYears(3);
        await store.ExtendExpiryAsync(key.Fingerprint, expiry, GeneratedKeys.Passphrase());
        var renewed = store.GetAllKeys().Single();
        renewed.ExpirationDate.Should().BeCloseTo(expiry, TimeSpan.FromSeconds(2));
        renewed.Fingerprint.Should().Be(key.Fingerprint);
        renewed.CanEncrypt.Should().BeTrue();
        string path = store.GetKeyFilePath(key.Fingerprint, false)!;
        var ring = SafetyRegressionTests.Read(File.ReadAllText(path));
        foreach (var packet in ring.GetPublicKeys())
            packet.CreationTime.AddSeconds(packet.GetValidSeconds()).Should().BeCloseTo(expiry, TimeSpan.FromSeconds(2));
    }

    [Fact]
    public async Task A_revocation_certificate_for_another_key_cannot_retire_the_selected_identity()
    {
        using var work = new TempWorkspace();
        var store = new KeyStoreService(keys.Service, work.Path("keys"));
        var key = await store.ImportKeyFromStringAsync(keys.Ed25519Private, true);
        Func<Task> apply = () => store.ApplyRevocationAsync(key.Fingerprint, keys.Rsa.RevocationCertificate);
        await apply.Should().ThrowAsync<Exception>();
        store.GetAllKeys().Single().IsRevoked.Should().BeFalse();
        await store.ApplyRevocationAsync(key.Fingerprint, keys.Ed25519.RevocationCertificate);
        store.GetAllKeys().Single().IsRevoked.Should().BeTrue();
    }

    [Fact]
    public async Task Repeated_generated_key_exports_have_distinct_names_and_preserve_previous_backups()
    {
        using var work = new TempWorkspace();
        var first = await KeyPairExportService.SaveAsync(work.Root, keys.Ed25519);
        var second = await KeyPairExportService.SaveAsync(work.Root, keys.Ed25519);
        first.Intersect(second).Should().BeEmpty();
        first.Concat(second).Should().OnlyContain(path => File.Exists(path));
        File.ReadAllText(first.Single(p => p.EndsWith("_private.asc", StringComparison.Ordinal))).Should().Be(keys.Ed25519Private);
    }
}
