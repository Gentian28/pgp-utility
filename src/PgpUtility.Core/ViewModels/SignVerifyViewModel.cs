using System.Collections.ObjectModel;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using PgpUtility.Models;
using PgpUtility.Services;

namespace PgpUtility.ViewModels;

public partial class SignVerifyViewModel : ViewModelBase
{
    private readonly IPgpSignatureService _signatures;
    private readonly IKeyStoreService _keyStoreService;
    private readonly IFilePickerService _filePicker;
    private readonly Action<string> _addLog;
    private readonly OperationRevision _revision = new();

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
        ReportFailure = addLog;
        RefreshKeys();
    }

    partial void OnPassphraseChanging(char[]? oldValue, char[] newValue) => ZeroIfReplaced(oldValue, newValue);

    partial void OnIsSignModeChanged(bool value)
    {
        // A verdict from the other mode would be stale and misleading the moment the mode flips.
        Invalidate();
        Passphrase = [];
        PassphraseCleared?.Invoke(this, EventArgs.Empty);
        RefreshKeys();
    }

    partial void OnFilePathChanged(string value) => Invalidate();
    partial void OnSignaturePathChanged(string value) => Invalidate();
    partial void OnSelectedKeyIdChanged(string? value) => Invalidate();
    private void Invalidate() { _revision.Next(); Result = null; StatusMessage = string.Empty; }

    public void RefreshKeys()
    {
        if (IsBusy) return;
        var keys = ReadKeys(_keyStoreService, Invalidate);
        if (keys is null) return;
        string? selected = SelectedKeyId;
        var before = AvailableKeys.FirstOrDefault(k => k.KeyId == selected);
        // Signing needs a secret key; verifying only needs the signer's public one. Offering keys
        // that cannot do the job just produces a confusing failure later.
        SynchronizeKeyChoices(AvailableKeys, keys.Where(key => !IsSignMode || (key.HasPrivateKey && key.CanSign)));
        SelectedKeyId = AvailableKeys.Any(k => k.KeyId == selected) ? selected : null;
        if (!SameKeyState(before, AvailableKeys.FirstOrDefault(k => k.KeyId == SelectedKeyId))) Invalidate();
    }

    [RelayCommand]
    private Task BrowseFileAsync() => GuardAsync(async () =>
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
    });

    [RelayCommand]
    private Task BrowseSignatureAsync() => GuardAsync(async () =>
    {
        string? file = await _filePicker.OpenFileAsync("Select the signature", PgpFileTypes.Signatures);
        if (file != null) SignaturePath = file;
    });

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
        int revision = _revision.Next();
        bool sign = IsSignMode;
        string input = FilePath;
        string selectedSignature = SignaturePath;
        bool armor = AsciiArmor;
        char[] passphrase = (char[])Passphrase.Clone();
        var progress = new Progress<string>(msg => { if (IsBusy && _revision.IsCurrent(revision)) { StatusMessage = msg; _addLog(msg); } });

        try
        {
            string? keyPath = _keyStoreService.GetKeyFilePath(SelectedKeyId!, privateKey: sign);
            if (keyPath == null)
            {
                StatusMessage = "That key is not in the store any more.";
                return;
            }

            if (sign)
            {
                string signaturePath = input + (armor ? ".asc" : ".sig");
                OperationResult signed = await _signatures.SignFileAsync(
                    input, signaturePath, keyPath, isFilePath: true, passphrase, armor, progress);

                if (!_revision.IsCurrent(revision)) return;
                if (signed.Success) SignaturePath = signaturePath;
                StatusMessage = signed.Message;
                _addLog(signed.Message);
            }
            else
            {
                var result = await _signatures.VerifyFileAsync(input, selectedSignature, keyPath, isFilePath: true, progress);
                if (!_revision.IsCurrent(revision)) return;
                Result = result;
                StatusMessage = Result.Message;
                _addLog(Result.Message);
            }
        }
        catch (Exception ex)
        {
            if (!_revision.IsCurrent(revision)) return;
            StatusMessage = $"Error: {ex.Message}";
            _addLog(StatusMessage);
        }
        finally
        {
            Array.Clear(passphrase);
            if (sign)
            {
                Passphrase = Array.Empty<char>();
                PassphraseCleared?.Invoke(this, EventArgs.Empty);
            }
            IsBusy = false;
            RefreshKeys();
        }
    }
}
