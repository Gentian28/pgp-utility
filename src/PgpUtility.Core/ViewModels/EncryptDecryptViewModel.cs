using System.Collections.ObjectModel;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using PgpUtility.Models;
using PgpUtility.Services;

namespace PgpUtility.ViewModels;

public partial class EncryptDecryptViewModel : ViewModelBase
{
    private readonly IPgpService _pgpService;
    private readonly IKeyStoreService _keyStoreService;
    private readonly IFilePickerService _filePicker;
    private readonly Action<string> _addLog;
    private CancellationTokenSource? _cts;

    [ObservableProperty]
    [NotifyCanExecuteChangedFor(nameof(ProcessCommand))]
    private bool _isEncryptMode = true;

    [ObservableProperty]
    [NotifyCanExecuteChangedFor(nameof(ProcessCommand))]
    private string? _selectedKeyId;

    [ObservableProperty]
    [NotifyCanExecuteChangedFor(nameof(ProcessCommand))]
    private string? _keyFilePath;

    [ObservableProperty]
    [NotifyCanExecuteChangedFor(nameof(ProcessCommand))]
    private bool _useKeyFromStore = true;

    [ObservableProperty]
    private char[] _passphrase = Array.Empty<char>();

    [ObservableProperty]
    [NotifyCanExecuteChangedFor(nameof(ProcessCommand))]
    private string _outputDirectory = string.Empty;

    [ObservableProperty]
    private bool _asciiArmor = true;

    [ObservableProperty]
    private double _progressValue;

    [ObservableProperty]
    private string _currentFileStatus = string.Empty;

    public ObservableCollection<BatchFileItem> Files { get; } = new();
    public ObservableCollection<PgpKeyInfo> AvailableKeys { get; } = new();

    /// <summary>
    /// Raised once the passphrase has been used and zeroed, so the view can empty its box rather
    /// than showing dots for a passphrase this view model no longer holds.
    /// </summary>
    public event EventHandler? PassphraseCleared;

    public EncryptDecryptViewModel(
        IPgpService pgpService,
        IKeyStoreService keyStoreService,
        IFilePickerService filePicker,
        Action<string> addLog)
    {
        _pgpService = pgpService;
        _keyStoreService = keyStoreService;
        _filePicker = filePicker;
        _addLog = addLog;
        ReportFailure = addLog;
        RefreshKeys();
    }

    partial void OnPassphraseChanging(char[]? oldValue, char[] newValue) => ZeroIfReplaced(oldValue, newValue);

    public void RefreshKeys()
    {
        if (IsBusy) return;
        string? selected = SelectedKeyId;
        AvailableKeys.Clear();
        foreach (var key in _keyStoreService.GetAllKeys())
            if (IsEncryptMode ? key.CanEncrypt : key.HasPrivateKey) AvailableKeys.Add(key);
        SelectedKeyId = AvailableKeys.Any(k => k.KeyId == selected) ? selected : null;
    }

    partial void OnIsEncryptModeChanged(bool value)
    {
        Passphrase = [];
        PassphraseCleared?.Invoke(this, EventArgs.Empty);
        RefreshKeys();
    }

    [RelayCommand]
    private Task AddFilesAsync() => GuardAsync(async () =>
    {
        var files = IsEncryptMode
            ? await _filePicker.OpenFilesAsync("Select files to encrypt")
            : await _filePicker.OpenFilesAsync("Select files to decrypt", PgpFileTypes.Encrypted);

        AddFilePaths(files);
    });

    public void AddFilePaths(IEnumerable<string> paths)
    {
        if (IsBusy) return;
        foreach (string path in paths)
        {
            if (Files.All(f => f.FilePath != path))
                Files.Add(new BatchFileItem(path));
        }
        ProcessCommand.NotifyCanExecuteChanged();
    }

    [RelayCommand]
    private void RemoveFile(BatchFileItem? item)
    {
        if (IsBusy) return;
        if (item != null)
        {
            Files.Remove(item);
            ProcessCommand.NotifyCanExecuteChanged();
        }
    }

    [RelayCommand]
    private void ClearFiles()
    {
        if (IsBusy) return;
        Files.Clear();
        ProcessCommand.NotifyCanExecuteChanged();
    }

    [RelayCommand]
    private Task BrowseKeyAsync() => GuardAsync(async () =>
    {
        string? file = await _filePicker.OpenFileAsync(
            IsEncryptMode ? "Select a public key" : "Select a private key",
            PgpFileTypes.Keys);

        if (file != null)
        {
            KeyFilePath = file;
            UseKeyFromStore = false;
        }
    });

    [RelayCommand]
    private Task BrowseOutputDirectoryAsync() => GuardAsync(async () =>
    {
        string? folder = await _filePicker.SelectFolderAsync("Select the output directory");
        if (folder != null)
            OutputDirectory = folder;
    });

    private bool CanProcess()
    {
        if (IsBusy) return false;
        if (Files.Count == 0) return false;
        if (string.IsNullOrWhiteSpace(OutputDirectory)) return false;
        if (UseKeyFromStore && string.IsNullOrEmpty(SelectedKeyId)) return false;
        if (!UseKeyFromStore && string.IsNullOrEmpty(KeyFilePath)) return false;
        return true;
    }

    [RelayCommand(CanExecute = nameof(CanProcess))]
    private async Task ProcessAsync()
    {
        IsBusy = true;
        ProcessCommand.NotifyCanExecuteChanged();
        _cts = new CancellationTokenSource();
        bool encrypt = IsEncryptMode;
        bool armor = AsciiArmor;
        bool fromStore = UseKeyFromStore;
        string? selectedKey = SelectedKeyId;
        string? keyFile = KeyFilePath;
        string directory = OutputDirectory;
        var files = Files.ToArray();
        var inputPaths = files.Select(f => f.FilePath).ToArray();
        char[] passphrase = (char[])Passphrase.Clone();
        ProgressValue = 0;
        foreach (var file in files) { file.Status = "Pending"; file.ErrorMessage = null; file.IsCompleted = false; file.IsProcessing = false; }
        var progress = new Progress<string>(msg =>
        {
            CurrentFileStatus = msg;
            _addLog(msg);
        });

        try
        {
            string keySource;

            if (fromStore)
            {
                string? keyPath = _keyStoreService.GetKeyFilePath(selectedKey!, !encrypt);
                if (keyPath == null)
                {
                    StatusMessage = "Key file not found in the store.";
                    return;
                }
                keySource = keyPath;
            }
            else
            {
                keySource = keyFile!;
            }

            var plan = BatchOutputPlan.Create(inputPaths, directory, encrypt, armor);
            int total = files.Length;
            int completed = 0;
            int failed = 0;
            int succeeded = 0;
            int cancelled = 0;

            for (int index = 0; index < total; index++)
            {
                if (_cts.Token.IsCancellationRequested) break;
                var file = files[index];

                file.Status = "Processing";
                file.IsProcessing = true;
                file.ErrorMessage = null;

                string outputPath = plan[index].OutputPath;

                OperationResult result;
                if (encrypt)
                {
                    result = await _pgpService.EncryptFileAsync(
                        inputPaths[index], outputPath, keySource, isFilePath: true,
                        armor, progress, _cts.Token);
                }
                else
                {
                    result = await _pgpService.DecryptFileAsync(
                        inputPaths[index], outputPath, keySource, isFilePath: true,
                        passphrase, progress, _cts.Token);
                }

                file.IsProcessing = false;
                if (result.Success)
                {
                    succeeded++;
                    // A message with no integrity check still decrypted, so this is not a failure,
                    // but it is not a verified result either and the row should not claim it is.
                    file.Status = result.Warning == null ? "Completed" : "Completed, unverified";
                    file.ErrorMessage = result.Warning;
                    file.IsCompleted = true;
                    _addLog($"Output: {outputPath}");
                    if (result.Warning != null)
                        _addLog(result.Warning);
                }
                else if (result.IsCanceled)
                {
                    cancelled++;
                    file.Status = "Cancelled";
                    file.ErrorMessage = result.Message;
                }
                else
                {
                    failed++;
                    file.Status = "Failed";
                    file.ErrorMessage = result.Message;
                }

                completed++;
                ProgressValue = (double)completed / total * 100;
            }

            if (_cts.Token.IsCancellationRequested)
                foreach (var file in files.Where(f => f.Status == "Pending")) file.Status = "Not processed";
            StatusMessage = $"Completed {succeeded}, failed {failed}, cancelled {cancelled}, unprocessed {total - completed}.";
            _addLog(StatusMessage);
        }
        catch (Exception ex)
        {
            StatusMessage = $"Error: {ex.Message}";
            _addLog(StatusMessage);
        }
        finally
        {
            // Zeroed at the end of every run rather than held for the session. The cost is
            // retyping it for the next batch; the gain is that it is not resident for however
            // long the app stays open.
            Array.Clear(passphrase);
            foreach (var file in files) file.IsProcessing = false;
            if (!encrypt)
            {
                Passphrase = Array.Empty<char>();
                PassphraseCleared?.Invoke(this, EventArgs.Empty);
            }

            IsBusy = false;
            RefreshKeys();
            ProcessCommand.NotifyCanExecuteChanged();
            _cts?.Dispose();
            _cts = null;
        }
    }

    [RelayCommand]
    private void Cancel()
    {
        _cts?.Cancel();
        _addLog("Cancellation requested.");
    }
}
