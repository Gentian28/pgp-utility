using System.Collections.ObjectModel;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using PgpUtility.App.Services;
using PgpUtility.Models;
using PgpUtility.Services;

namespace PgpUtility.App.ViewModels;

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
        RefreshKeys();
    }

    partial void OnPassphraseChanging(char[]? oldValue, char[] newValue) => ZeroIfReplaced(oldValue, newValue);

    public void RefreshKeys()
    {
        AvailableKeys.Clear();
        foreach (var key in _keyStoreService.GetAllKeys())
            AvailableKeys.Add(key);
    }

    [RelayCommand]
    private async Task AddFilesAsync()
    {
        var files = IsEncryptMode
            ? await _filePicker.OpenFilesAsync("Select files to encrypt")
            : await _filePicker.OpenFilesAsync("Select files to decrypt", PgpFileTypes.Encrypted);

        AddFilePaths(files);
    }

    public void AddFilePaths(IEnumerable<string> paths)
    {
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
        if (item != null)
        {
            Files.Remove(item);
            ProcessCommand.NotifyCanExecuteChanged();
        }
    }

    [RelayCommand]
    private void ClearFiles()
    {
        Files.Clear();
        ProcessCommand.NotifyCanExecuteChanged();
    }

    [RelayCommand]
    private async Task BrowseKeyAsync()
    {
        string? file = await _filePicker.OpenFileAsync(
            IsEncryptMode ? "Select a public key" : "Select a private key",
            PgpFileTypes.Keys);

        if (file != null)
        {
            KeyFilePath = file;
            UseKeyFromStore = false;
        }
    }

    [RelayCommand]
    private async Task BrowseOutputDirectoryAsync()
    {
        string? folder = await _filePicker.SelectFolderAsync("Select the output directory");
        if (folder != null)
            OutputDirectory = folder;
    }

    private bool CanProcess()
    {
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
        _cts = new CancellationTokenSource();
        var progress = new Progress<string>(msg =>
        {
            CurrentFileStatus = msg;
            _addLog(msg);
        });

        try
        {
            string keySource;

            if (UseKeyFromStore)
            {
                string? keyPath = _keyStoreService.GetKeyFilePath(SelectedKeyId!, !IsEncryptMode);
                if (keyPath == null)
                {
                    StatusMessage = "Key file not found in the store.";
                    return;
                }
                keySource = keyPath;
            }
            else
            {
                keySource = KeyFilePath!;
            }

            int total = Files.Count;
            int completed = 0;

            foreach (var file in Files)
            {
                if (_cts.Token.IsCancellationRequested) break;

                file.Status = "Processing";
                file.IsProcessing = true;
                file.ErrorMessage = null;

                string outputFileName = IsEncryptMode
                    ? Path.GetFileName(file.FilePath) + (AsciiArmor ? ".asc" : ".pgp")
                    : StripEncryptedExtension(file.FilePath);
                string outputPath = Path.Combine(OutputDirectory, outputFileName);

                OperationResult result;
                if (IsEncryptMode)
                {
                    result = await _pgpService.EncryptFileAsync(
                        file.FilePath, outputPath, keySource, isFilePath: true,
                        AsciiArmor, progress, _cts.Token);
                }
                else
                {
                    result = await _pgpService.DecryptFileAsync(
                        file.FilePath, outputPath, keySource, isFilePath: true,
                        Passphrase, progress, _cts.Token);
                }

                file.IsProcessing = false;
                if (result.Success)
                {
                    // A message with no integrity check still decrypted, so this is not a failure,
                    // but it is not a verified result either and the row should not claim it is.
                    file.Status = result.Warning == null ? "Completed" : "Completed, unverified";
                    file.ErrorMessage = result.Warning;
                    file.IsCompleted = true;
                    if (result.Warning != null)
                        _addLog(result.Warning);
                }
                else
                {
                    file.Status = "Failed";
                    file.ErrorMessage = result.Message;
                }

                completed++;
                ProgressValue = (double)completed / total * 100;
            }

            StatusMessage = _cts.Token.IsCancellationRequested
                ? "Operation cancelled."
                : $"Processed {completed} of {total} files.";
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
            if (!IsEncryptMode)
            {
                Passphrase = Array.Empty<char>();
                PassphraseCleared?.Invoke(this, EventArgs.Empty);
            }

            IsBusy = false;
            _cts?.Dispose();
            _cts = null;
        }
    }

    /// <summary>
    /// Drops one encryption extension so "report.pdf.asc" decrypts to "report.pdf".
    /// </summary>
    /// <remarks>
    /// Only for extensions this app adds. Blindly taking the name without its extension turned
    /// "archive.tar.gz" into "archive.tar" on a file that was never encrypted by us.
    /// </remarks>
    private static string StripEncryptedExtension(string path)
    {
        string name = Path.GetFileName(path);
        foreach (string extension in new[] { ".pgp", ".gpg", ".asc" })
        {
            if (name.EndsWith(extension, StringComparison.OrdinalIgnoreCase))
                return name[..^extension.Length];
        }
        return name + ".decrypted";
    }

    [RelayCommand]
    private void Cancel()
    {
        _cts?.Cancel();
        _addLog("Cancellation requested.");
    }
}
