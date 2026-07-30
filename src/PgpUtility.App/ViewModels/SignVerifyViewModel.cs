using System.Collections.ObjectModel;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using PgpUtility.App.Services;
using PgpUtility.Models;
using PgpUtility.Services;

namespace PgpUtility.App.ViewModels;

public partial class SignVerifyViewModel : ViewModelBase
{
    private readonly IPgpSignatureService _signatures;
    private readonly IKeyStoreService _keyStoreService;
    private readonly IFilePickerService _filePicker;
    private readonly Action<string> _addLog;

    public event EventHandler? PassphraseCleared;

    [ObservableProperty]
    [NotifyCanExecuteChangedFor(nameof(RunCommand))]
    [NotifyPropertyChangedFor(nameof(IsVerifyMode))]
    private bool _isSignMode = true;

    [ObservableProperty]
    [NotifyCanExecuteChangedFor(nameof(RunCommand))]
    private string _filePath = string.Empty;

    [ObservableProperty]
    [NotifyCanExecuteChangedFor(nameof(RunCommand))]
    private string _signaturePath = string.Empty;

    [ObservableProperty]
    [NotifyCanExecuteChangedFor(nameof(RunCommand))]
    private string? _selectedKeyId;

    [ObservableProperty]
    private char[] _passphrase = Array.Empty<char>();

    [ObservableProperty]
    private bool _asciiArmor = true;

    /// <summary>Null until a verification has run, so the view shows nothing rather than "unknown".</summary>
    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(HasResult))]
    private SignatureVerification? _result;

    public bool IsVerifyMode => !IsSignMode;

    public bool HasResult => Result != null;

    public ObservableCollection<PgpKeyInfo> AvailableKeys { get; } = new();

    public SignVerifyViewModel(
        IPgpSignatureService signatures,
        IKeyStoreService keyStoreService,
        IFilePickerService filePicker,
        Action<string> addLog)
    {
        _signatures = signatures;
        _keyStoreService = keyStoreService;
        _filePicker = filePicker;
        _addLog = addLog;
        RefreshKeys();
    }

    partial void OnPassphraseChanging(char[]? oldValue, char[] newValue) => ZeroIfReplaced(oldValue, newValue);

    partial void OnIsSignModeChanged(bool value)
    {
        // A verdict from the other mode would be stale and misleading the moment the mode flips.
        Result = null;
        RefreshKeys();
    }

    public void RefreshKeys()
    {
        AvailableKeys.Clear();

        // Signing needs a secret key; verifying only needs the signer's public one. Offering keys
        // that cannot do the job just produces a confusing failure later.
        foreach (var key in _keyStoreService.GetAllKeys())
        {
            if (!IsSignMode || key.HasPrivateKey)
                AvailableKeys.Add(key);
        }
    }

    [RelayCommand]
    private async Task BrowseFileAsync()
    {
        string? file = await _filePicker.OpenFileAsync(
            IsSignMode ? "Select a file to sign" : "Select the file to check");
        if (file != null)
        {
            FilePath = file;
            // The signature almost always sits beside the file with a .sig suffix, so offering
            // that saves a second trip through the picker in the common case.
            if (IsVerifyMode && string.IsNullOrEmpty(SignaturePath) && File.Exists(file + ".sig"))
                SignaturePath = file + ".sig";
        }
    }

    [RelayCommand]
    private async Task BrowseSignatureAsync()
    {
        string? file = await _filePicker.OpenFileAsync("Select the signature", PgpFileTypes.Signatures);
        if (file != null) SignaturePath = file;
    }

    public void AcceptDroppedFiles(IReadOnlyList<string> paths)
    {
        foreach (string path in paths)
        {
            bool looksLikeSignature =
                path.EndsWith(".sig", StringComparison.OrdinalIgnoreCase) ||
                path.EndsWith(".asc", StringComparison.OrdinalIgnoreCase);

            // In verify mode a dropped .sig goes to the signature box and anything else to the
            // file box, so dropping both in either order lands them correctly.
            if (IsVerifyMode && looksLikeSignature)
                SignaturePath = path;
            else
                FilePath = path;
        }
    }

    private bool CanRun()
    {
        if (string.IsNullOrWhiteSpace(FilePath)) return false;
        if (string.IsNullOrEmpty(SelectedKeyId)) return false;
        if (IsVerifyMode && string.IsNullOrWhiteSpace(SignaturePath)) return false;
        return true;
    }

    [RelayCommand(CanExecute = nameof(CanRun))]
    private async Task RunAsync()
    {
        IsBusy = true;
        Result = null;
        var progress = new Progress<string>(msg => { StatusMessage = msg; _addLog(msg); });

        try
        {
            string? keyPath = _keyStoreService.GetKeyFilePath(SelectedKeyId!, privateKey: IsSignMode);
            if (keyPath == null)
            {
                StatusMessage = "That key is not in the store any more.";
                return;
            }

            if (IsSignMode)
            {
                string signaturePath = FilePath + (AsciiArmor ? ".asc" : ".sig");
                OperationResult signed = await _signatures.SignFileAsync(
                    FilePath, signaturePath, keyPath, isFilePath: true, Passphrase, AsciiArmor, progress);

                StatusMessage = signed.Message;
                _addLog(signed.Message);
                if (signed.Success) SignaturePath = signaturePath;
            }
            else
            {
                Result = await _signatures.VerifyFileAsync(
                    FilePath, SignaturePath, keyPath, isFilePath: true, progress);
                StatusMessage = Result.Message;
                _addLog(Result.Message);
            }
        }
        catch (Exception ex)
        {
            StatusMessage = $"Error: {ex.Message}";
            _addLog(StatusMessage);
        }
        finally
        {
            if (IsSignMode)
            {
                Passphrase = Array.Empty<char>();
                PassphraseCleared?.Invoke(this, EventArgs.Empty);
            }
            IsBusy = false;
        }
    }
}
