using System.Text;
using PgpUtility.Models;
using PgpUtility.Services;
using PgpUtility.ViewModels;

namespace PgpUtility.Tests;

// These exercise real services through the UI's commands. They are simulated task flows,
// not observations of real participants or native keyboard/pointer testing.
[Collection(KeyCollection.Name)]
public class SimulatedUserJourneyTests(GeneratedKeys keys)
{
    [Fact]
    public async Task First_time_user_generates_saves_and_receives_a_message()
    {
        using var work = new TempWorkspace();
        var store = new KeyStoreService(keys.Service, work.Path("store"));
        var picker = new Picker { Folder = work.Root };
        var clipboard = new Clipboard();
        var vm = new KeyGenerationViewModel(keys.Service, store, picker, clipboard, _ => { })
        { Name = "Synthetic first user", Email = "first@example.invalid", HasExpiration = true, ExpirationDate = DateTimeOffset.Now.AddYears(1) };
        char[] passphrase = "synthetic first passphrase".ToCharArray();
        vm.Passphrase = passphrase;
        vm.ConfirmPassphrase = "synthetic first passphrase".ToCharArray();
        vm.GenerateCommand.CanExecute(null).Should().BeTrue();
        await vm.GenerateCommand.ExecuteAsync(null);
        vm.KeysGenerated.Should().BeTrue(vm.StatusMessage);
        passphrase.Should().OnlyContain(c => c == '\0');
        await vm.SaveKeysCommand.ExecuteAsync(null);
        Directory.GetFiles(work.Root, "*.asc").Should().HaveCount(3);
        await vm.ImportToStoreCommand.ExecuteAsync(null);
        var key = store.GetAllKeys().Single();
        key.HasPrivateKey.Should().BeTrue();
        await vm.CopyPublicKeyCommand.ExecuteAsync(null);
        clipboard.Text.Should().Be(vm.GeneratedPublicKey);
        clipboard.Text.Should().NotContain("PRIVATE KEY");
        var encrypted = await keys.Service.EncryptTextAsync("first successful exchange", clipboard.Text!, false);
        var text = new TextViewModel(keys.Service, keys.Signatures, store, clipboard, _ => { })
        { SelectedAction = TextViewModel.TextAction.Decrypt, SelectedKeyId = key.KeyId, Input = encrypted.Payload!, Passphrase = "synthetic first passphrase".ToCharArray() };
        await text.RunCommand.ExecuteAsync(null);
        text.Output.Should().Be("first successful exchange");
        text.Passphrase.Should().BeEmpty();
    }

    [Fact]
    public async Task File_user_exchanges_same_named_documents_without_overwriting_anything()
    {
        using var work = new TempWorkspace();
        foreach (string name in new[] { "one", "two", "encrypted", "decrypted" }) Directory.CreateDirectory(work.Path(name));
        string first = work.WriteFile("one/report.txt", "one document"u8.ToArray());
        string second = work.WriteFile("two/report.txt", "two documents"u8.ToArray());
        string existing = work.WriteFile("encrypted/report.txt.asc", "already here"u8.ToArray());
        var store = await Store(work);
        var picker = new Picker { Files = [first, second] };
        var encrypt = new EncryptDecryptViewModel(keys.Service, store, picker, _ => { })
        { SelectedKeyId = store.GetAllKeys().Single().KeyId, OutputDirectory = work.Path("encrypted") };
        await encrypt.AddFilesCommand.ExecuteAsync(null);
        await encrypt.ProcessCommand.ExecuteAsync(null);
        encrypt.Files.Should().OnlyContain(f => f.IsCompleted);
        File.ReadAllText(existing).Should().Be("already here");
        string[] encrypted = Directory.GetFiles(work.Path("encrypted"), "*.asc").Where(p => Path.GetFullPath(p) != Path.GetFullPath(existing)).ToArray();
        encrypted.Should().HaveCount(2);
        var decrypt = new EncryptDecryptViewModel(keys.Service, store, new Picker(), _ => { })
        { IsEncryptMode = false, SelectedKeyId = store.GetAllKeys().Single().KeyId, OutputDirectory = work.Path("decrypted"), Passphrase = GeneratedKeys.Passphrase() };
        decrypt.AddFilePaths(encrypted);
        await decrypt.ProcessCommand.ExecuteAsync(null);
        decrypt.Files.Should().OnlyContain(f => f.IsCompleted);
        Directory.GetFiles(work.Path("decrypted")).Select(File.ReadAllText).Should().BeEquivalentTo(new[] { "one document", "two documents" });
        File.ReadAllText(first).Should().Be("one document");
        File.ReadAllText(second).Should().Be("two documents");
        decrypt.Passphrase.Should().BeEmpty();
    }

    [Fact]
    public async Task Signature_user_distinguishes_unavailable_good_and_changed_content()
    {
        using var work = new TempWorkspace();
        var store = await Store(work);
        var other = await store.ImportKeyFromStringAsync(keys.RsaPublic, false);
        string file = work.WriteFile("report.txt", "original document"u8.ToArray());
        string signature = work.Path("report.sig");
        (await keys.Signatures.SignFileAsync(file, signature, keys.Ed25519Private, false, GeneratedKeys.Passphrase(), false)).Success.Should().BeTrue();
        var vm = new SignVerifyViewModel(keys.Signatures, store, new Picker(), _ => { })
        { IsSignMode = false, FilePath = file, SignaturePath = signature, SelectedKeyId = other.KeyId };
        await vm.RunCommand.ExecuteAsync(null);
        vm.Result!.Completed.Should().BeFalse();
        vm.Result.Headline.Should().Be("Unable to check the signature");
        vm.SelectedKeyId = store.GetAllKeys().Single(k => k.HasPrivateKey).KeyId;
        vm.HasResult.Should().BeFalse();
        await vm.RunCommand.ExecuteAsync(null);
        vm.Result!.IsValid.Should().BeTrue();
        vm.Result.PrimaryFingerprint.Should().Be(store.GetAllKeys().Single(k => k.HasPrivateKey).Fingerprint);
        File.WriteAllText(file, "changed document");
        await vm.RunCommand.ExecuteAsync(null);
        vm.Result!.IsInvalid.Should().BeTrue();
        vm.Result.Headline.Should().Be("Signature does not match");
        vm.SignaturePath = "a different signature";
        vm.HasResult.Should().BeFalse();
    }

    [Fact]
    public async Task Recovery_user_restores_a_backup_into_an_empty_store_and_opens_an_old_message()
    {
        using var work = new TempWorkspace();
        var source = await Store(work);
        var sourceKey = source.GetAllKeys().Single();
        await source.SaveRevocationCertificateAsync(sourceKey.Fingerprint, keys.Ed25519.RevocationCertificate);
        var encrypted = await keys.Service.EncryptTextAsync("before the backup", keys.Ed25519Public, false);
        string backup = work.Path("backup.zip");
        var picker = new Picker { Save = backup, Open = backup };
        var manager = Manager(source, picker);
        manager.BackUpKeysCommand.Execute(null);
        await manager.ConfirmBackupCommand.ExecuteAsync(null);
        File.Exists(backup).Should().BeTrue(manager.StatusMessage);
        var restored = new KeyStoreService(keys.Service, work.Path("restored"));
        var recovery = Manager(restored, picker);
        recovery.RestoreBackupCommand.Execute(null);
        await recovery.ConfirmRestoreCommand.ExecuteAsync(null);
        recovery.Keys.Should().ContainSingle().Which.Fingerprint.Should().Be(sourceKey.Fingerprint);
        recovery.StatusMessage.Should().Contain("Restored 1");
        var text = new TextViewModel(keys.Service, keys.Signatures, restored, new Clipboard(), _ => { })
        { SelectedAction = TextViewModel.TextAction.Decrypt, SelectedKeyId = restored.GetAllKeys().Single().KeyId, Input = encrypted.Payload!, Passphrase = GeneratedKeys.Passphrase() };
        await text.RunCommand.ExecuteAsync(null);
        text.Output.Should().Be("before the backup");
        string certificate = work.Path("restored-certificate.asc");
        await restored.ExportRevocationCertificateAsync(sourceKey.Fingerprint, certificate, []);
        File.ReadAllText(certificate).Should().Be(keys.Ed25519.RevocationCertificate);
    }

    [Fact]
    public async Task Existing_user_renews_changes_passphrase_revokes_and_safely_deletes_a_key()
    {
        using var work = new TempWorkspace();
        var store = await Store(work);
        var before = store.GetAllKeys().Single();
        var encrypted = await keys.Service.EncryptTextAsync("historical message", keys.Ed25519Public, false);
        string certificate = work.Path("certificate.asc");
        var picker = new Picker { Save = certificate, Open = certificate };
        var vm = Manager(store, picker);
        vm.SelectedKey = vm.Keys.Single();
        vm.ManageKeyCommand.Execute("renew");
        vm.NewExpiry = DateTimeOffset.Now.AddYears(3);
        vm.CurrentPassphrase = GeneratedKeys.Passphrase();
        await vm.ApplyKeyActionCommand.ExecuteAsync(null);
        store.GetAllKeys().Single().ExpirationDate.Should().BeAfter(DateTime.UtcNow.AddYears(2));
        const string next = "synthetic new caf\u00e9 secret";
        vm.ManageKeyCommand.Execute("password");
        vm.CurrentPassphrase = GeneratedKeys.Passphrase();
        vm.NewPassphrase = next.ToCharArray();
        vm.ConfirmNewPassphrase = next.ToCharArray();
        await vm.ApplyKeyActionCommand.ExecuteAsync(null);
        vm.CurrentPassphrase.Should().BeEmpty();
        vm.NewPassphrase.Should().BeEmpty();
        vm.ManageKeyCommand.Execute("certificate");
        vm.CurrentPassphrase = next.ToCharArray();
        await vm.ApplyKeyActionCommand.ExecuteAsync(null);
        File.Exists(certificate).Should().BeTrue(vm.StatusMessage);
        vm.ManageKeyCommand.Execute("revoke");
        await vm.ApplyKeyActionCommand.ExecuteAsync(null);
        var retired = store.GetAllKeys().Single();
        retired.Fingerprint.Should().Be(before.Fingerprint);
        retired.IsRevoked.Should().BeTrue(vm.StatusMessage);
        retired.CanEncrypt.Should().BeFalse();
        retired.CanSign.Should().BeFalse();
        var old = await keys.Service.DecryptTextAsync(encrypted.Payload!, store.GetKeyFilePath(retired.Fingerprint, true)!, true, next.ToCharArray());
        old.Payload.Should().Be("historical message");
        vm.DeleteKeyCommand.Execute(null);
        vm.CancelDeleteCommand.Execute(null);
        store.GetAllKeys().Should().ContainSingle();
        vm.DeleteKeyCommand.Execute(null);
        await vm.ConfirmDeleteKeyCommand.ExecuteAsync(null);
        store.GetAllKeys().Should().BeEmpty();
    }

    private async Task<KeyStoreService> Store(TempWorkspace work)
    {
        var store = new KeyStoreService(keys.Service, work.Path("store"));
        await store.ImportKeyFromStringAsync(keys.Ed25519Private, true);
        return store;
    }

    private KeyManagementViewModel Manager(IKeyStoreService store, Picker picker) =>
        new(store, keys.Service, picker, new Clipboard(), _ => { });

    private sealed class Clipboard : IClipboardService
    {
        public string? Text { get; private set; }
        public Task<string?> GetTextAsync() => Task.FromResult(Text);
        public Task SetTextAsync(string text) { Text = text; return Task.CompletedTask; }
    }

    private sealed class Picker : IFilePickerService
    {
        public string? Save { get; init; }
        public string? Open { get; init; }
        public string? Folder { get; init; }
        public IReadOnlyList<string> Files { get; init; } = [];
        public Task<string?> OpenFileAsync(string title, params PgpFileType[] fileTypes) => Task.FromResult(Open);
        public Task<IReadOnlyList<string>> OpenFilesAsync(string title, params PgpFileType[] fileTypes) => Task.FromResult(Files);
        public Task<string?> SaveFileAsync(string title, string suggestedFileName, params PgpFileType[] fileTypes) => Task.FromResult(Save);
        public Task<string?> SelectFolderAsync(string title) => Task.FromResult(Folder);
    }
}
