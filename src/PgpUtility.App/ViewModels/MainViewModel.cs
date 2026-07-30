using System.Collections.ObjectModel;
using Avalonia.Threading;
using CommunityToolkit.Mvvm.ComponentModel;
using PgpUtility.App.Services;
using PgpUtility.Services;

namespace PgpUtility.App.ViewModels;

public partial class MainViewModel : ViewModelBase
{
    /// <summary>
    /// Caps the log so a long session cannot grow it without bound. It is a running commentary,
    /// not an audit trail, and nothing reads it back.
    /// </summary>
    private const int MaxLogEntries = 500;

    [ObservableProperty]
    private int _selectedTabIndex;

    [ObservableProperty]
    private bool _isLogPanelVisible;

    // Every tab reads the same key store, so a key added on one has to appear on the others
    // without a restart. Refreshing on tab change is cheap and needs no change notification
    // plumbed through the store.
    partial void OnSelectedTabIndexChanged(int value)
    {
        EncryptDecryptVm.RefreshKeys();
        SignVerifyVm.RefreshKeys();
        TextVm.RefreshKeys();
        KeyManagementVm.RefreshKeys();
    }

    public ObservableCollection<string> LogEntries { get; } = new();

    public EncryptDecryptViewModel EncryptDecryptVm { get; }
    public SignVerifyViewModel SignVerifyVm { get; }
    public TextViewModel TextVm { get; }
    public KeyManagementViewModel KeyManagementVm { get; }
    public KeyGenerationViewModel KeyGenerationVm { get; }

    public MainViewModel(
        IPgpService pgpService,
        IPgpSignatureService signatures,
        IKeyStoreService keyStoreService,
        IFilePickerService filePicker,
        IClipboardService clipboard)
    {
        EncryptDecryptVm = new EncryptDecryptViewModel(pgpService, keyStoreService, filePicker, AddLog);
        SignVerifyVm = new SignVerifyViewModel(signatures, keyStoreService, filePicker, AddLog);
        TextVm = new TextViewModel(pgpService, signatures, keyStoreService, clipboard, AddLog);
        KeyManagementVm = new KeyManagementViewModel(keyStoreService, pgpService, filePicker, clipboard, AddLog);
        KeyGenerationVm = new KeyGenerationViewModel(pgpService, keyStoreService, filePicker, clipboard, AddLog);
    }

    public void AddLog(string message)
    {
        // Progress arrives from a thread pool thread. Post rather than invoke: the caller is
        // reporting, not waiting for the UI to catch up, and blocking it would slow the work.
        Dispatcher.UIThread.Post(() =>
        {
            LogEntries.Add($"[{DateTime.Now:HH:mm:ss}] {message}");
            while (LogEntries.Count > MaxLogEntries)
                LogEntries.RemoveAt(0);

            StatusMessage = message;
        });
    }
}
