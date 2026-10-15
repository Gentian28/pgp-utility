using System.Collections.ObjectModel;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using PgpUtility.Models;
using PgpUtility.Services;

namespace PgpUtility.ViewModels;

public partial class KeyManagementViewModel : ViewModelBase
{
    private string? _deletionFingerprint;
    public event EventHandler? PassphraseCleared;
    public event EventHandler? GenerationRequested;

    [RelayCommand]
    private void CreateKey() => GenerationRequested?.Invoke(this, EventArgs.Empty);

    [ObservableProperty]
    private bool _isDeleteConfirmationVisible;

    [ObservableProperty]
    private bool _isBackupConfirmationVisible;

    [ObservableProperty]
    private bool _isRestoreConfirmationVisible;

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(IsRenewing))]
    [NotifyPropertyChangedFor(nameof(IsChangingPassphrase))]
    [NotifyPropertyChangedFor(nameof(IsExportingCertificate))]
    [NotifyPropertyChangedFor(nameof(IsApplyingRevocation))]
    [NotifyPropertyChangedFor(nameof(HasKeyAction))]
    [NotifyPropertyChangedFor(nameof(NeedsCurrentPassphrase))]
    [NotifyPropertyChangedFor(nameof(KeyActionLabel))]
    private string _keyAction = string.Empty;

    [ObservableProperty]
    private DateTimeOffset _newExpiry = DateTimeOffset.Now.AddYears(2);

    [ObservableProperty]
    private char[] _currentPassphrase = [];

    [ObservableProperty]
    private char[] _newPassphrase = [];

    [ObservableProperty]
    private char[] _confirmNewPassphrase = [];

    public bool IsRenewing => KeyAction == "renew";
    public bool IsChangingPassphrase => KeyAction == "password";
    public bool IsExportingCertificate => KeyAction == "certificate";
    public bool IsApplyingRevocation => KeyAction == "revoke";
    public bool HasKeyAction => KeyAction.Length > 0;
    public bool NeedsCurrentPassphrase => HasKeyAction && !IsApplyingRevocation;
    public string KeyActionLabel => KeyAction switch
    {
        "renew" => "Extend expiry", "password" => "Change passphrase", "certificate" => "Save certificate",
        "revoke" => "Choose and apply certificate", _ => "Continue"
    };
    private readonly IKeyStoreService _keyStoreService;
    private readonly IPgpService _pgpService;
    private readonly IFilePickerService _filePicker;
    private readonly IClipboardService _clipboard;
    private readonly Action<string> _addLog;

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(HasSelection))]
    [NotifyPropertyChangedFor(nameof(SelectedHasPrivateKey))]
    private PgpKeyInfo? _selectedKey;

    [ObservableProperty]
    private string _searchText = string.Empty;

    public ObservableCollection<PgpKeyInfo> Keys { get; } = new();
    public ObservableCollection<PgpKeyInfo> FilteredKeys { get; } = new();

    public bool HasSelection => SelectedKey != null;

    public bool SelectedHasPrivateKey => SelectedKey?.HasPrivateKey == true;

    public KeyManagementViewModel(
        IKeyStoreService keyStoreService,
        IPgpService pgpService,
        IFilePickerService filePicker,
        IClipboardService clipboard,
        Action<string> addLog)
    {
        _keyStoreService = keyStoreService;
        _pgpService = pgpService;
        _filePicker = filePicker;
        _clipboard = clipboard;
        _addLog = addLog;
        ReportFailure = addLog;
        RefreshKeys();
    }

    partial void OnSearchTextChanged(string value) => ApplyFilter();
    partial void OnSelectedKeyChanged(PgpKeyInfo? value)
    {
        IsDeleteConfirmationVisible = false;
        _deletionFingerprint = null;
        KeyAction = string.Empty;
        ClearPassphrases();
    }
    partial void OnCurrentPassphraseChanging(char[]? oldValue, char[] newValue) => ZeroIfReplaced(oldValue, newValue);
    partial void OnNewPassphraseChanging(char[]? oldValue, char[] newValue) => ZeroIfReplaced(oldValue, newValue);
    partial void OnConfirmNewPassphraseChanging(char[]? oldValue, char[] newValue) => ZeroIfReplaced(oldValue, newValue);

    private void ClearPassphrases()
    {
        CurrentPassphrase = []; NewPassphrase = []; ConfirmNewPassphrase = [];
        PassphraseCleared?.Invoke(this, EventArgs.Empty);
    }

    public void RefreshKeys()
    {
        string? selected = SelectedKey?.Fingerprint;
        Keys.Clear();
        foreach (var key in _keyStoreService.GetAllKeys())
            Keys.Add(key);
        ApplyFilter();
        SelectedKey = Keys.FirstOrDefault(k => k.Fingerprint == selected);
    }

    private void ApplyFilter()
    {
        FilteredKeys.Clear();
        string filter = SearchText.Trim();
        foreach (var key in Keys)
        {
            if (string.IsNullOrEmpty(filter) ||
                key.UserId.Contains(filter, StringComparison.OrdinalIgnoreCase) ||
                key.KeyId.Contains(filter, StringComparison.OrdinalIgnoreCase) ||
                key.Fingerprint.Contains(filter, StringComparison.OrdinalIgnoreCase))
            {
                FilteredKeys.Add(key);
            }
        }
    }

    [RelayCommand]
    private Task ImportKeyAsync() => GuardAsync(async () =>
    {
        string? file = await _filePicker.OpenFileAsync("Import a key", PgpFileTypes.Keys);
        if (file == null) return;

        IsBusy = true;
        try
        {
            PgpKeyInfo info = await _keyStoreService.ImportKeyAsync(file, isFilePath: true);
            _addLog($"Imported key: {info.UserId}");

            RefreshKeys();
            StatusMessage = $"Key imported: {info.UserId}";
        }
        catch (Exception ex)
        {
            StatusMessage = $"Import failed: {ex.Message}";
            _addLog(StatusMessage);
        }
        finally
        {
            IsBusy = false;
        }
    });

    [RelayCommand]
    private Task ImportFromClipboardAsync() => GuardAsync(async () =>
    {
        string? text = await _clipboard.GetTextAsync();
        if (string.IsNullOrWhiteSpace(text))
        {
            StatusMessage = "The clipboard does not contain any text.";
            return;
        }

        IsBusy = true;
        try
        {
            PgpKeyInfo info = await _keyStoreService.ImportKeyAsync(text, isFilePath: false);
            RefreshKeys();
            StatusMessage = $"Key imported from the clipboard: {info.UserId}";
            _addLog(StatusMessage);
        }
        catch (Exception ex)
        {
            StatusMessage = $"Import failed: {ex.Message}";
            _addLog(StatusMessage);
        }
        finally
        {
            IsBusy = false;
        }
    });

    [RelayCommand]
    private async Task ExportPublicKeyAsync() => await GuardAsync(() => ExportAsync(exportPrivate: false));

    [RelayCommand]
    private async Task ExportPrivateKeyAsync() => await GuardAsync(() => ExportAsync(exportPrivate: true));

    private async Task ExportAsync(bool exportPrivate)
    {
        if (IsBusy || SelectedKey == null) return;
        string fingerprint = SelectedKey.Fingerprint;

        string suffix = exportPrivate ? "private" : "public";
        string? file = await _filePicker.SaveFileAsync(
            exportPrivate ? "Export the private key" : "Export the public key",
            $"{fingerprint}_{suffix}.asc",
            PgpFileTypes.Keys);
        if (file == null) return;

        IsBusy = true;
        try
        {
            await _keyStoreService.ExportKeyAsync(fingerprint, file, exportPrivate);
            StatusMessage = exportPrivate
                ? $"Private key exported to {file}. Treat that file like a password."
                : $"Public key exported to {file}";
            _addLog(StatusMessage);
        }
        catch (Exception ex)
        {
            StatusMessage = $"Export failed: {ex.Message}";
            _addLog(StatusMessage);
        }
        finally
        {
            IsBusy = false;
        }
    }

    [RelayCommand]
    private void DeleteKey()
    {
        if (IsBusy || SelectedKey is null) return;
        _deletionFingerprint = SelectedKey.Fingerprint;
        IsDeleteConfirmationVisible = true;
    }

    [RelayCommand]
    private void CancelDelete()
    {
        IsDeleteConfirmationVisible = false;
        _deletionFingerprint = null;
    }

    [RelayCommand]
    private async Task ConfirmDeleteKeyAsync()
    {
        if (IsBusy || SelectedKey is null || !IsDeleteConfirmationVisible || _deletionFingerprint != SelectedKey.Fingerprint) return;

        IsBusy = true;
        try
        {
            string userId = SelectedKey.UserId;
            await _keyStoreService.DeleteKeyAsync(_deletionFingerprint);
            SelectedKey = null;
            RefreshKeys();
            StatusMessage = $"Key deleted: {userId}";
            _addLog(StatusMessage);
        }
        catch (Exception ex)
        {
            StatusMessage = $"Delete failed: {ex.Message}";
            _addLog(StatusMessage);
        }
        finally
        {
            IsBusy = false;
        }
    }

    [RelayCommand]
    private void BackUpKeys() { if (!IsBusy) IsBackupConfirmationVisible = true; }

    [RelayCommand]
    private void RestoreBackup() { if (!IsBusy) IsRestoreConfirmationVisible = true; }

    [RelayCommand]
    private void CancelBackup() { IsBackupConfirmationVisible = false; IsRestoreConfirmationVisible = false; }

    [RelayCommand]
    private Task ConfirmBackupAsync() => GuardAsync(async () =>
    {
        if (IsBusy || !IsBackupConfirmationVisible) return;
        IsBusy = true;
        try
        {
            string? path = await _filePicker.SaveFileAsync("Back up keys and revocation certificates",
                "PgpUtility-backup-" + DateTime.Now.ToString("yyyyMMdd-HHmmss") + ".zip", PgpFileTypes.Backups);
            if (path is null) return;
            await _keyStoreService.ExportBackupAsync(path);
            IsBackupConfirmationVisible = false;
            StatusMessage = "Backup saved. Keep it offline and test a restore before relying on it.";
            _addLog(StatusMessage);
        }
        finally { IsBusy = false; }
    });

    [RelayCommand]
    private Task ConfirmRestoreAsync() => GuardAsync(async () =>
    {
        if (IsBusy || !IsRestoreConfirmationVisible) return;
        IsBusy = true;
        try
        {
            string? path = await _filePicker.OpenFileAsync("Restore a PGP Utility backup", PgpFileTypes.Backups);
            if (path is null) return;
            int count = await _keyStoreService.RestoreBackupAsync(path);
            RefreshKeys();
            IsRestoreConfirmationVisible = false;
            StatusMessage = $"Restored {count} identities. Decrypt a previously encrypted message to check access.";
            _addLog(StatusMessage);
        }
        finally { IsBusy = false; }
    });

    [RelayCommand]
    private void ManageKey(string? action)
    {
        if (IsBusy || SelectedKey is null || action is not ("renew" or "password" or "certificate" or "revoke")) return;
        KeyAction = action;
        ClearPassphrases();
    }

    [RelayCommand]
    private void CancelKeyAction() { KeyAction = string.Empty; ClearPassphrases(); }

    [RelayCommand]
    private Task ApplyKeyActionAsync() => GuardAsync(async () =>
    {
        if (IsBusy || SelectedKey is null || !HasKeyAction) return;
        string fingerprint = SelectedKey.Fingerprint;
        string action = KeyAction;
        DateTime expiry = NewExpiry.Date.AddDays(1).AddTicks(-1).ToUniversalTime();
        char[] current = (char[])CurrentPassphrase.Clone();
        char[] next = (char[])NewPassphrase.Clone();
        char[] confirmation = (char[])ConfirmNewPassphrase.Clone();
        IsBusy = true;
        try
        {
            switch (action)
            {
                case "renew":
                    await _keyStoreService.ExtendExpiryAsync(fingerprint, expiry, current);
                    StatusMessage = "Expiry extended. Share the updated public key with your correspondents.";
                    break;
                case "password":
                    if (!next.AsSpan().SequenceEqual(confirmation)) throw new ArgumentException("The new passphrases do not match.");
                    await _keyStoreService.ChangePassphraseAsync(fingerprint, current, next);
                    StatusMessage = "Passphrase changed. Older backups still use the previous passphrase. Create a new backup.";
                    break;
                case "certificate":
                    string? output = await _filePicker.SaveFileAsync("Save the revocation certificate", fingerprint + "_revocation.asc", PgpFileTypes.Keys);
                    if (output is null) return;
                    await _keyStoreService.ExportRevocationCertificateAsync(fingerprint, output, current);
                    StatusMessage = "Revocation certificate saved. Keep it separately; anyone holding it can retire this key.";
                    break;
                case "revoke":
                    string? input = await _filePicker.OpenFileAsync("Apply the revocation certificate for this fingerprint", PgpFileTypes.Keys);
                    if (input is null) return;
                    if (new FileInfo(input).Length > 16 * 1024 * 1024) throw new IOException("This certificate is too large.");
                    await _keyStoreService.ApplyRevocationAsync(fingerprint, await File.ReadAllTextAsync(input));
                    StatusMessage = "Key revoked. Old messages remain decryptable. Share the updated public key with your correspondents.";
                    break;
            }
            KeyAction = string.Empty;
            RefreshKeys();
            _addLog(StatusMessage);
        }
        finally { Array.Clear(current); Array.Clear(next); Array.Clear(confirmation); ClearPassphrases(); IsBusy = false; }
    });

    [RelayCommand]
    private Task CopyPublicKeyAsync() => GuardAsync(async () =>
    {
        if (SelectedKey == null) return;

        string? keyPath = _keyStoreService.GetKeyFilePath(SelectedKey.Fingerprint, privateKey: false);
        if (keyPath == null)
        {
            StatusMessage = "The public key file was not found.";
            return;
        }

        await _clipboard.SetTextAsync(await File.ReadAllTextAsync(keyPath));
        StatusMessage = "Public key copied to the clipboard.";
        _addLog(StatusMessage);
    });

    [RelayCommand]
    private Task CopyFingerprintAsync() => GuardAsync(async () =>
    {
        if (SelectedKey == null) return;
        await _clipboard.SetTextAsync(SelectedKey.Fingerprint);
        StatusMessage = "Fingerprint copied to the clipboard.";
    });
}
