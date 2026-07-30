using System.Collections.ObjectModel;
using CommunityToolkit.Mvvm.ComponentModel;
using PgpUtility.Services;

namespace PgpUtility.ViewModels;

public partial class MainViewModel : ViewModelBase
{
    [ObservableProperty]
    private int _selectedTabIndex;

    [ObservableProperty]
    private bool _isLogPanelVisible;

    partial void OnSelectedTabIndexChanged(int value)
    {
        EncryptDecryptVm.RefreshKeys();
        KeyManagementVm.RefreshKeys();
    }

    public ObservableCollection<string> LogEntries { get; } = new();

    public EncryptDecryptViewModel EncryptDecryptVm { get; }
    public KeyManagementViewModel KeyManagementVm { get; }
    public KeyGenerationViewModel KeyGenerationVm { get; }

    public MainViewModel(
        IPgpService pgpService,
        IKeyStoreService keyStoreService,
        IFileDialogService fileDialogService)
    {
        EncryptDecryptVm = new EncryptDecryptViewModel(pgpService, keyStoreService, fileDialogService, AddLog);
        KeyManagementVm = new KeyManagementViewModel(keyStoreService, pgpService, fileDialogService, AddLog);
        KeyGenerationVm = new KeyGenerationViewModel(pgpService, keyStoreService, AddLog);
    }

    public void AddLog(string message)
    {
        var timestamp = DateTime.Now.ToString("HH:mm:ss");
        System.Windows.Application.Current?.Dispatcher.Invoke(() =>
        {
            LogEntries.Add($"[{timestamp}] {message}");
            StatusMessage = message;
        });
    }
}
