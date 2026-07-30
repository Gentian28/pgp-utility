using System.Collections.ObjectModel;
using System.IO;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using PgpUtility.Models;
using PgpUtility.Services;

namespace PgpUtility.ViewModels;

public partial class EncryptDecryptViewModel : ViewModelBase
{
    private readonly IPgpService _pgpService;
    private readonly IKeyStoreService _keyStoreService;
    private readonly IFileDialogService _fileDialogService;
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
    /// Raised once the passphrase has been used and zeroed, so the view can empty its password
    /// box rather than showing dots for a passphrase this view model no longer holds.
    /// </summary>
    public event EventHandler? PassphraseCleared;

    public EncryptDecryptViewModel(
        IPgpService pgpService,
        IKeyStoreService keyStoreService,
        IFileDialogService fileDialogService,
        Action<string> addLog)
    {
        _pgpService = pgpService;
        _keyStoreService = keyStoreService;
        _fileDialogService = fileDialogService;
        _addLog = addLog;
        RefreshKeys();
    }

    // Zero whatever the field held before it is replaced, so a passphrase does not accumulate one
    // abandoned copy per keystroke.
    partial void OnPassphraseChanging(char[]? oldValue, char[] newValue)
    {
        if (oldValue is not null && !ReferenceEquals(oldValue, newValue))
            Array.Clear(oldValue);
    }

    public void RefreshKeys()
    {
        AvailableKeys.Clear();
        foreach (var key in _keyStoreService.GetAllKeys())
            AvailableKeys.Add(key);
    }

    [RelayCommand]
    private void AddFiles()
    {
        string filter = IsEncryptMode
            ? "All Files (*.*)|*.*"
            : "PGP Files (*.pgp;*.gpg;*.asc)|*.pgp;*.gpg;*.asc|All Files (*.*)|*.*";
        var files = _fileDialogService.OpenFiles("Select Files", filter);
        if (files != null)
            AddFilePaths(files);
    }

    public void AddFilePaths(string[] paths)
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
    private void BrowseKey()
    {
        var file = _fileDialogService.OpenFile(
            IsEncryptMode ? "Select Public Key" : "Select Private Key",
            "Key Files (*.asc;*.gpg;*.pub;*.sec)|*.asc;*.gpg;*.pub;*.sec|All Files (*.*)|*.*");
        if (file != null)
        {
            KeyFilePath = file;
            UseKeyFromStore = false;
        }
    }

    [RelayCommand]
    private void BrowseOutputDirectory()
    {
        var folder = _fileDialogService.SelectFolder("Select Output Directory");
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
            bool isFilePath;

            if (UseKeyFromStore)
            {
                var keyPath = _keyStoreService.GetKeyFilePath(SelectedKeyId!, !IsEncryptMode);
                if (keyPath == null)
                {
                    StatusMessage = "Key file not found in store.";
                    return;
                }
                keySource = keyPath;
                isFilePath = true;
            }
            else
            {
                keySource = KeyFilePath!;
                isFilePath = true;
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
                    ? Path.GetFileName(file.FilePath) + ".pgp"
                    : Path.GetFileNameWithoutExtension(file.FilePath);
                string outputPath = Path.Combine(OutputDirectory, outputFileName);

                OperationResult result;
                if (IsEncryptMode)
                {
                    result = await _pgpService.EncryptFileAsync(
                        file.FilePath, outputPath, keySource, isFilePath,
                        AsciiArmor, progress, _cts.Token);
                }
                else
                {
                    result = await _pgpService.DecryptFileAsync(
                        file.FilePath, outputPath, keySource, isFilePath,
                        Passphrase, progress, _cts.Token);
                }

                file.IsProcessing = false;
                if (result.Success)
                {
                    // A message with no integrity check still decrypted, so this is not a failure,
                    // but it is not the same as a verified one either and the row should not claim
                    // it is.
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
            // retyping it for the next batch; the gain is that it is not sitting in memory
            // for however long the app stays open.
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

    [RelayCommand]
    private void Cancel()
    {
        _cts?.Cancel();
        _addLog("Cancellation requested.");
    }
}
