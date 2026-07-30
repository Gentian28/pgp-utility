using System.Collections.ObjectModel;
using System.IO;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using PgpUtility.Models;
using PgpUtility.Services;

namespace PgpUtility.ViewModels;

public partial class KeyManagementViewModel : ViewModelBase
{
    private readonly IKeyStoreService _keyStoreService;
    private readonly IPgpService _pgpService;
    private readonly IFileDialogService _fileDialogService;
    private readonly Action<string> _addLog;

    [ObservableProperty]
    private PgpKeyInfo? _selectedKey;

    [ObservableProperty]
    private string _searchText = string.Empty;

    public ObservableCollection<PgpKeyInfo> Keys { get; } = new();
    public ObservableCollection<PgpKeyInfo> FilteredKeys { get; } = new();

    public KeyManagementViewModel(
        IKeyStoreService keyStoreService,
        IPgpService pgpService,
        IFileDialogService fileDialogService,
        Action<string> addLog)
    {
        _keyStoreService = keyStoreService;
        _pgpService = pgpService;
        _fileDialogService = fileDialogService;
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
        var filter = SearchText.Trim();
        foreach (var key in Keys)
        {
            if (string.IsNullOrEmpty(filter) ||
                key.UserId.Contains(filter, StringComparison.OrdinalIgnoreCase) ||
                key.KeyId.Contains(filter, StringComparison.OrdinalIgnoreCase))
            {
                FilteredKeys.Add(key);
            }
        }
    }

    [RelayCommand]
    private async Task ImportKeyAsync()
    {
        var file = _fileDialogService.OpenFile("Import Key",
            "Key Files (*.asc;*.gpg;*.pub;*.sec)|*.asc;*.gpg;*.pub;*.sec|All Files (*.*)|*.*");
        if (file == null) return;

        IsBusy = true;
        try
        {
            // Try public first, then private
            PgpKeyInfo info;
            try
            {
                info = await _keyStoreService.ImportPublicKeyAsync(file);
                _addLog($"Imported public key: {info.UserId}");
            }
            catch
            {
                info = await _keyStoreService.ImportPrivateKeyAsync(file);
                _addLog($"Imported private key: {info.UserId}");
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
    private async Task ExportKeyAsync()
    {
        if (SelectedKey == null) return;

        var file = _fileDialogService.SaveFile("Export Key",
            "ASCII Armored (*.asc)|*.asc|All Files (*.*)|*.*",
            $"{SelectedKey.KeyId}.asc");
        if (file == null) return;

        IsBusy = true;
        try
        {
            await _keyStoreService.ExportKeyAsync(SelectedKey.KeyId, file, false);
            StatusMessage = $"Key exported to {file}";
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
    private void CopyPublicKey()
    {
        if (SelectedKey == null) return;

        var keyPath = _keyStoreService.GetKeyFilePath(SelectedKey.KeyId, false);
        if (keyPath == null)
        {
            StatusMessage = "Public key file not found.";
            return;
        }

        string keyContent = File.ReadAllText(keyPath);
        System.Windows.Clipboard.SetText(keyContent);
        StatusMessage = "Public key copied to clipboard.";
        _addLog(StatusMessage);
    }
}
