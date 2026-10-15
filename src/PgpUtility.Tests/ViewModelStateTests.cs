using PgpUtility.Models;
using PgpUtility.Services;
using PgpUtility.ViewModels;

namespace PgpUtility.Tests;

[Collection(KeyCollection.Name)]
public class ViewModelStateTests(GeneratedKeys keys)
{
    private async Task<KeyStoreService> Store(TempWorkspace work)
    {
        var store = new KeyStoreService(keys.Service, work.Path("store"));
        await store.ImportKeyFromStringAsync(keys.Ed25519Private, true);
        return store;
    }

    [Fact]
    public async Task Editing_text_during_verification_discards_the_old_verdict()
    {
        using var work = new TempWorkspace();
        var signatures = new DeferredSignatures();
        var store = await Store(work);
        var vm = new TextViewModel(keys.Service, signatures, store, new Clipboard(), _ => { })
        { SelectedAction = TextViewModel.TextAction.Verify, Input = "original", SelectedKeyId = store.GetAllKeys().Single().KeyId };
        Task running = vm.RunCommand.ExecuteAsync(null);
        await signatures.Started.Task.WaitAsync(TimeSpan.FromSeconds(10));
        vm.Input = "changed";
        signatures.Finish.SetResult(Good());
        await running;
        vm.Result.Should().BeNull();
        vm.Output.Should().BeEmpty();
        vm.StatusMessage.Should().BeEmpty();
    }

    [Fact]
    public async Task Editing_a_detached_signature_path_clears_and_supersedes_a_verdict()
    {
        using var work = new TempWorkspace();
        var signatures = new DeferredSignatures();
        var store = await Store(work);
        var vm = new SignVerifyViewModel(signatures, store, new Picker(), _ => { })
        { IsSignMode = false, FilePath = "original", SignaturePath = "original.sig", SelectedKeyId = store.GetAllKeys().Single().KeyId };
        Task running = vm.RunCommand.ExecuteAsync(null);
        await signatures.Started.Task.WaitAsync(TimeSpan.FromSeconds(10));
        vm.SignaturePath = "different.sig";
        signatures.Finish.SetResult(Good());
        await running;
        vm.Result.Should().BeNull();
        vm.StatusMessage.Should().BeEmpty();
        vm.Result = Good();
        vm.FilePath = "different";
        vm.HasResult.Should().BeFalse();
    }

    [Fact]
    public async Task Mode_changes_and_clear_zero_the_array_and_notify_the_view()
    {
        using var work = new TempWorkspace();
        var vm = new TextViewModel(keys.Service, keys.Signatures, await Store(work), new Clipboard(), _ => { });
        int cleared = 0;
        vm.PassphraseCleared += (_, _) => cleared++;
        char[] first = "synthetic secret".ToCharArray();
        vm.Passphrase = first;
        vm.SelectedAction = TextViewModel.TextAction.Decrypt;
        first.Should().OnlyContain(c => c == '\0');
        char[] second = "another synthetic secret".ToCharArray();
        vm.Passphrase = second;
        vm.ClearCommand.Execute(null);
        second.Should().OnlyContain(c => c == '\0');
        cleared.Should().Be(2);
    }

    [Fact]
    public async Task An_active_batch_uses_its_snapshot_and_ignores_list_mutation_commands()
    {
        using var work = new TempWorkspace();
        Directory.CreateDirectory(work.Path("before"));
        var service = new DeferredPgp(keys.Service);
        var store = await Store(work);
        var vm = new EncryptDecryptViewModel(service, store, new Picker(), _ => { })
        { SelectedKeyId = store.GetAllKeys().Single().KeyId, OutputDirectory = work.Path("before"), AsciiArmor = true };
        vm.AddFilePaths([work.Path("one.txt"), work.Path("two.txt")]);
        Task running = vm.ProcessCommand.ExecuteAsync(null);
        await service.Started.Task.WaitAsync(TimeSpan.FromSeconds(10));
        vm.ClearFilesCommand.Execute(null);
        vm.RemoveFileCommand.Execute(vm.Files[0]);
        vm.AddFilePaths([work.Path("three.txt")]);
        vm.Files.Count.Should().Be(2);
        vm.IsEncryptMode = false;
        vm.AsciiArmor = false;
        vm.OutputDirectory = work.Path("after");
        service.Finish.SetResult(OperationResult.Succeeded("done"));
        await running;
        service.Calls.Should().HaveCount(2);
        service.Calls.Should().OnlyContain(c => c.Encrypt && c.Armor && Path.GetDirectoryName(c.Output) == work.Path("before"));
        vm.Files.Should().OnlyContain(f => f.IsCompleted);
        vm.StatusMessage.Should().Contain("Completed 2, failed 0");
    }

    [Fact]
    public async Task Switching_key_source_notifies_command_availability()
    {
        using var work = new TempWorkspace();
        var vm = new EncryptDecryptViewModel(keys.Service, await Store(work), new Picker(), _ => { })
        { KeyFilePath = work.Path("external.asc"), OutputDirectory = work.Path("output") };
        vm.AddFilePaths([work.Path("input")]);
        vm.ProcessCommand.CanExecute(null).Should().BeFalse();
        int changed = 0;
        vm.ProcessCommand.CanExecuteChanged += (_, _) => changed++;
        vm.UseKeyFromStore = false;
        changed.Should().BeGreaterThan(0);
        vm.ProcessCommand.CanExecute(null).Should().BeTrue();
    }

    [Fact]
    public async Task Deletion_requires_confirmation_for_the_same_fingerprint()
    {
        using var work = new TempWorkspace();
        var store = await Store(work);
        await store.ImportKeyFromStringAsync(keys.RsaPublic, false);
        var vm = new KeyManagementViewModel(store, keys.Service, new Picker(), new Clipboard(), _ => { });
        vm.SelectedKey = vm.Keys[0];
        await vm.ConfirmDeleteKeyCommand.ExecuteAsync(null);
        store.GetAllKeys().Should().HaveCount(2);
        vm.DeleteKeyCommand.Execute(null);
        store.GetAllKeys().Should().HaveCount(2);
        vm.SelectedKey = vm.Keys[1];
        vm.IsDeleteConfirmationVisible.Should().BeFalse();
        await vm.ConfirmDeleteKeyCommand.ExecuteAsync(null);
        store.GetAllKeys().Should().HaveCount(2);
        string fingerprint = vm.SelectedKey.Fingerprint;
        vm.DeleteKeyCommand.Execute(null);
        await vm.ConfirmDeleteKeyCommand.ExecuteAsync(null);
        store.GetAllKeys().Should().ContainSingle().Which.Fingerprint.Should().NotBe(fingerprint);
    }

    [Fact]
    public async Task Clipboard_and_picker_errors_are_reported_without_unhandled_commands()
    {
        using var work = new TempWorkspace();
        var clipboard = new Clipboard { Fail = true };
        var vm = new TextViewModel(keys.Service, keys.Signatures, await Store(work), clipboard, _ => { });
        await vm.PasteCommand.ExecuteAsync(null);
        vm.StatusMessage.Should().Contain("clipboard unavailable");
        var manager = new KeyManagementViewModel(await Store(work), keys.Service, new Picker { Fail = true }, clipboard, _ => { });
        await manager.ImportKeyCommand.ExecuteAsync(null);
        manager.StatusMessage.Should().Contain("picker unavailable");
        manager.IsBusy.Should().BeFalse();
    }

    [Fact]
    public void Incomplete_verification_has_a_distinct_headline()
    {
        SignatureVerification.Failed("missing key").Headline.Should().Be("Unable to check the signature");
        SignatureVerification.Invalid("changed bytes").Headline.Should().Be("Signature does not match");
        Good().Headline.Should().Be("Signature is good");
    }

    private static SignatureVerification Good() => SignatureVerification.Valid("good", "synthetic", "Test", DateTime.UtcNow);

    private sealed class Clipboard : IClipboardService
    {
        public bool Fail { get; init; }
        public Task<string?> GetTextAsync() => Fail ? Task.FromException<string?>(new IOException("clipboard unavailable")) : Task.FromResult<string?>(null);
        public Task SetTextAsync(string text) => Task.CompletedTask;
    }

    private sealed class Picker : IFilePickerService
    {
        public bool Fail { get; init; }
        public Task<string?> OpenFileAsync(string title, params PgpFileType[] fileTypes) => Fail ? Task.FromException<string?>(new IOException("picker unavailable")) : Task.FromResult<string?>(null);
        public Task<IReadOnlyList<string>> OpenFilesAsync(string title, params PgpFileType[] fileTypes) => Task.FromResult<IReadOnlyList<string>>([]);
        public Task<string?> SaveFileAsync(string title, string suggestedFileName, params PgpFileType[] fileTypes) => Task.FromResult<string?>(null);
        public Task<string?> SelectFolderAsync(string title) => Task.FromResult<string?>(null);
    }

    private sealed class DeferredSignatures : IPgpSignatureService
    {
        public TaskCompletionSource Started { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
        public TaskCompletionSource<SignatureVerification> Finish { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
        public Task<SignatureVerification> VerifyFileAsync(string inputFilePath, string signatureFilePath, string publicKeySource, bool isFilePath, IProgress<string>? progress = null, CancellationToken cancellationToken = default)
        { Started.TrySetResult(); return Finish.Task; }
        public Task<SignatureVerification> VerifyTextAsync(string clearSignedText, string publicKeySource, bool isFilePath, CancellationToken cancellationToken = default)
        { Started.TrySetResult(); return Finish.Task; }
        public Task<OperationResult> SignFileAsync(string inputFilePath, string signatureFilePath, string privateKeySource, bool isFilePath, char[] passphrase, bool armor, IProgress<string>? progress = null, CancellationToken cancellationToken = default) => throw new NotSupportedException();
        public Task<OperationResult> SignTextAsync(string text, string privateKeySource, bool isFilePath, char[] passphrase, CancellationToken cancellationToken = default) => throw new NotSupportedException();
    }

    private sealed class DeferredPgp(IPgpService real) : IPgpService
    {
        public List<(bool Encrypt, bool Armor, string Output)> Calls { get; } = [];
        public TaskCompletionSource Started { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
        public TaskCompletionSource<OperationResult> Finish { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
        public Task<OperationResult> EncryptFileAsync(string inputFilePath, string outputFilePath, string publicKeySource, bool isFilePath, bool armor, IProgress<string>? progress = null, CancellationToken cancellationToken = default)
        { Calls.Add((true, armor, outputFilePath)); Started.TrySetResult(); return Finish.Task; }
        public Task<OperationResult> DecryptFileAsync(string inputFilePath, string outputFilePath, string privateKeySource, bool isFilePath, char[] passphrase, IProgress<string>? progress = null, CancellationToken cancellationToken = default)
        { Calls.Add((false, false, outputFilePath)); return Finish.Task; }
        public Task<GeneratedKeyPair> GenerateKeyPairAsync(KeyGenerationOptions options, IProgress<string>? progress = null, CancellationToken cancellationToken = default) => throw new NotSupportedException();
        public string CreateRevocationCertificate(string privateKeySource, bool isFilePath, char[] passphrase) => throw new NotSupportedException();
        public Task<OperationResult> EncryptTextAsync(string text, string publicKeySource, bool isFilePath, CancellationToken cancellationToken = default) => throw new NotSupportedException();
        public Task<OperationResult> DecryptTextAsync(string armoredText, string privateKeySource, bool isFilePath, char[] passphrase, CancellationToken cancellationToken = default) => throw new NotSupportedException();
        public PgpKeyInfo ReadPublicKeyInfo(string keySource, bool isFilePath) => real.ReadPublicKeyInfo(keySource, isFilePath);
        public PgpKeyInfo ReadPrivateKeyInfo(string keySource, bool isFilePath) => real.ReadPrivateKeyInfo(keySource, isFilePath);
        public string ExtractPublicKeyFromPrivateKey(string privateKeySource, bool isFilePath) => real.ExtractPublicKeyFromPrivateKey(privateKeySource, isFilePath);
    }
}
