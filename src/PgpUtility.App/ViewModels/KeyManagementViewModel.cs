using System.Collections.ObjectModel;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using PgpUtility.App.Services;
using PgpUtility.Models;
using PgpUtility.Services;

namespace PgpUtility.App.ViewModels;

public partial class KeyManagementViewModel : ViewModelBase
{
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
        RefreshKeys();
    }

    partial void OnSearchTextChanged(string value) => ApplyFilter();

    public void RefreshKeys()
    {
        Keys.Clear();
        foreach (var key in _keyStoreService.GetAllKeys())
            Keys.Add(key);
        ApplyFilter();
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
    private async Task ImportKeyAsync()
    {
        string? file = await _filePicker.OpenFileAsync("Import a key", PgpFileTypes.Keys);
        if (file == null) return;

        IsBusy = true;
        try
        {
            // A file holding a secret key also holds its public half, so the private import is
            // tried first. The other order silently imports only the public key and the user is
            // left wondering why they cannot decrypt.
            PgpKeyInfo info;
            try
            {
                info = await _keyStoreService.ImportPrivateKeyAsync(file);
                _addLog($"Imported private key: {info.UserId}");
            }
            catch
            {
                info = await _keyStoreService.ImportPublicKeyAsync(file);
                _addLog($"Imported public key: {info.UserId}");
            }

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
    }

    [RelayCommand]
    private async Task ImportFromClipboardAsync()
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
            bool isPrivate = text.Contains("PRIVATE KEY BLOCK", StringComparison.OrdinalIgnoreCase);
            PgpKeyInfo info = await _keyStoreService.ImportKeyFromStringAsync(text, isPrivate);
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
    }

    [RelayCommand]
    private async Task ExportPublicKeyAsync() => await ExportAsync(exportPrivate: false);

    [RelayCommand]
    private async Task ExportPrivateKeyAsync() => await ExportAsync(exportPrivate: true);

    private async Task ExportAsync(bool exportPrivate)
    {
        if (SelectedKey == null) return;

        string suffix = exportPrivate ? "private" : "public";
        string? file = await _filePicker.SaveFileAsync(
            exportPrivate ? "Export the private key" : "Export the public key",
            $"{SelectedKey.KeyId}_{suffix}.asc",
            PgpFileTypes.Keys);
        if (file == null) return;

        IsBusy = true;
        try
        {
            await _keyStoreService.ExportKeyAsync(SelectedKey.KeyId, file, exportPrivate);
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
    private async Task DeleteKeyAsync()
    {
        if (SelectedKey == null) return;

        IsBusy = true;
        try
        {
            string userId = SelectedKey.UserId;
            await _keyStoreService.DeleteKeyAsync(SelectedKey.KeyId);
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
    private async Task CopyPublicKeyAsync()
    {
        if (SelectedKey == null) return;

        string? keyPath = _keyStoreService.GetKeyFilePath(SelectedKey.KeyId, privateKey: false);
        if (keyPath == null)
        {
            StatusMessage = "The public key file was not found.";
            return;
        }

        await _clipboard.SetTextAsync(await File.ReadAllTextAsync(keyPath));
        StatusMessage = "Public key copied to the clipboard.";
        _addLog(StatusMessage);
    }

    [RelayCommand]
    private async Task CopyFingerprintAsync()
    {
        if (SelectedKey == null) return;
        await _clipboard.SetTextAsync(SelectedKey.Fingerprint);
        StatusMessage = "Fingerprint copied to the clipboard.";
    }
}
