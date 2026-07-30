using System.IO;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using PgpUtility.Models;
using PgpUtility.Services;

namespace PgpUtility.ViewModels;

public partial class KeyGenerationViewModel : ViewModelBase
{
    private readonly IPgpService _pgpService;
    private readonly IKeyStoreService _keyStoreService;
    private readonly Action<string> _addLog;

    [ObservableProperty]
    [NotifyCanExecuteChangedFor(nameof(GenerateCommand))]
    private string _name = string.Empty;

    [ObservableProperty]
    private string _email = string.Empty;

    [ObservableProperty]
    [NotifyCanExecuteChangedFor(nameof(GenerateCommand))]
    private string _passphrase = string.Empty;

    [ObservableProperty]
    [NotifyCanExecuteChangedFor(nameof(GenerateCommand))]
    private string _confirmPassphrase = string.Empty;

    [ObservableProperty]
    private int _selectedKeySize = 2048;

    [ObservableProperty]
    private bool _hasExpiration;

    [ObservableProperty]
    private DateTime _expirationDate = DateTime.Now.AddYears(1);

    [ObservableProperty]
    private string _generatedPublicKey = string.Empty;

    [ObservableProperty]
    private string _generatedPrivateKey = string.Empty;

    [ObservableProperty]
    private bool _keysGenerated;

    public int[] KeySizes { get; } = [2048, 4096];

    public KeyGenerationViewModel(
        IPgpService pgpService,
        IKeyStoreService keyStoreService,
        Action<string> addLog)
    {
        _pgpService = pgpService;
        _keyStoreService = keyStoreService;
        _addLog = addLog;
    }

    private bool CanGenerate() =>
        !string.IsNullOrWhiteSpace(Name) &&
        !string.IsNullOrWhiteSpace(Passphrase) &&
        Passphrase == ConfirmPassphrase;

    [RelayCommand(CanExecute = nameof(CanGenerate))]
    private async Task GenerateAsync()
    {
        IsBusy = true;
        KeysGenerated = false;
        var progress = new Progress<string>(msg =>
        {
            StatusMessage = msg;
            _addLog(msg);
        });

        try
        {
            var options = new KeyGenerationOptions
            {
                Name = Name,
                Email = Email,
                Passphrase = Passphrase,
                KeySize = SelectedKeySize,
                ExpirationDate = HasExpiration ? ExpirationDate : null
            };

            var (publicKey, privateKey) = await _pgpService.GenerateKeyPairAsync(options, progress);
            GeneratedPublicKey = publicKey;
            GeneratedPrivateKey = privateKey;
            KeysGenerated = true;
            StatusMessage = "Key pair generated successfully.";
        }
        catch (Exception ex)
        {
            StatusMessage = $"Key generation failed: {ex.Message}";
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
        if (!string.IsNullOrEmpty(GeneratedPublicKey))
        {
            System.Windows.Clipboard.SetText(GeneratedPublicKey);
            StatusMessage = "Public key copied to clipboard.";
        }
    }

    [RelayCommand]
    private void CopyPrivateKey()
    {
        if (!string.IsNullOrEmpty(GeneratedPrivateKey))
        {
            System.Windows.Clipboard.SetText(GeneratedPrivateKey);
            StatusMessage = "Private key copied to clipboard.";
        }
    }

    [RelayCommand]
    private async Task SaveKeysAsync()
    {
        if (!KeysGenerated) return;

        var folder = new FileDialogService().SelectFolder("Select folder to save keys");
        if (folder == null) return;

        try
        {
            string identity = new KeyGenerationOptions { Name = Name, Email = Email }.Identity;
            string safeName = string.Join("_", identity.Split(Path.GetInvalidFileNameChars()));

            await File.WriteAllTextAsync(
                Path.Combine(folder, $"{safeName}_public.asc"), GeneratedPublicKey);
            await File.WriteAllTextAsync(
                Path.Combine(folder, $"{safeName}_private.asc"), GeneratedPrivateKey);

            StatusMessage = "Keys saved to disk.";
            _addLog(StatusMessage);
        }
        catch (Exception ex)
        {
            StatusMessage = $"Save failed: {ex.Message}";
            _addLog(StatusMessage);
        }
    }

    [RelayCommand]
    private async Task ImportToStoreAsync()
    {
        if (!KeysGenerated) return;

        IsBusy = true;
        try
        {
            await _keyStoreService.ImportKeyFromStringAsync(GeneratedPublicKey, false);
            await _keyStoreService.ImportKeyFromStringAsync(GeneratedPrivateKey, true);
            StatusMessage = "Keys imported to key store.";
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
}
