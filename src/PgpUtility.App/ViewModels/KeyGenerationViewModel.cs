using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using PgpUtility.App.Services;
using PgpUtility.Models;
using PgpUtility.Services;

namespace PgpUtility.App.ViewModels;

/// <summary>
/// One entry in the algorithm dropdown. Wraps the enum so the list can carry a label without the
/// view having to know how to spell each algorithm.
/// </summary>
public sealed record AlgorithmChoice(PgpKeyAlgorithm Value, string Display);

public partial class KeyGenerationViewModel : ViewModelBase
{
    private readonly IPgpService _pgpService;
    private readonly IKeyStoreService _keyStoreService;
    private readonly IFilePickerService _filePicker;
    private readonly IClipboardService _clipboard;
    private readonly Action<string> _addLog;

    /// <summary>
    /// Raised once the passphrase has been used and zeroed, so the view can empty its boxes.
    /// Without it the fields would still show dots for a passphrase this view model no longer
    /// holds, and the next Generate would fail on an empty array.
    /// </summary>
    public event EventHandler? PassphraseCleared;

    [ObservableProperty]
    [NotifyCanExecuteChangedFor(nameof(GenerateCommand))]
    private string _name = string.Empty;

    [ObservableProperty]
    private string _email = string.Empty;

    [ObservableProperty]
    [NotifyCanExecuteChangedFor(nameof(GenerateCommand))]
    private char[] _passphrase = Array.Empty<char>();

    [ObservableProperty]
    [NotifyCanExecuteChangedFor(nameof(GenerateCommand))]
    private char[] _confirmPassphrase = Array.Empty<char>();

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(IsRsaSelected))]
    private PgpKeyAlgorithm _selectedAlgorithm = PgpKeyAlgorithm.Ed25519;

    [ObservableProperty]
    private int _selectedKeySize = 4096;

    [ObservableProperty]
    private bool _hasExpiration;

    [ObservableProperty]
    private DateTimeOffset _expirationDate = DateTimeOffset.Now.AddYears(2);

    [ObservableProperty]
    private string _generatedPublicKey = string.Empty;

    [ObservableProperty]
    private string _generatedPrivateKey = string.Empty;

    [ObservableProperty]
    private bool _keysGenerated;

    public AlgorithmChoice[] Algorithms { get; } =
    [
        new(PgpKeyAlgorithm.Ed25519, "Ed25519 (recommended)"),
        new(PgpKeyAlgorithm.Rsa, "RSA")
    ];

    /// <summary>Key size only means something for RSA; Ed25519's is fixed by the curve.</summary>
    public bool IsRsaSelected => SelectedAlgorithm == PgpKeyAlgorithm.Rsa;

    public int[] KeySizes { get; } = [2048, 4096];

    public KeyGenerationViewModel(
        IPgpService pgpService,
        IKeyStoreService keyStoreService,
        IFilePickerService filePicker,
        IClipboardService clipboard,
        Action<string> addLog)
    {
        _pgpService = pgpService;
        _keyStoreService = keyStoreService;
        _filePicker = filePicker;
        _clipboard = clipboard;
        _addLog = addLog;
    }

    partial void OnPassphraseChanging(char[]? oldValue, char[] newValue) => ZeroIfReplaced(oldValue, newValue);

    partial void OnConfirmPassphraseChanging(char[]? oldValue, char[] newValue) => ZeroIfReplaced(oldValue, newValue);

    private bool CanGenerate() =>
        !string.IsNullOrWhiteSpace(Name) &&
        Passphrase.Length > 0 &&
        Passphrase.AsSpan().SequenceEqual(ConfirmPassphrase);

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
                Algorithm = SelectedAlgorithm,
                KeySize = SelectedKeySize,
                ExpirationDate = HasExpiration ? ExpirationDate.UtcDateTime : null
            };

            var (publicKey, privateKey) = await _pgpService.GenerateKeyPairAsync(options, progress);
            GeneratedPublicKey = publicKey;
            GeneratedPrivateKey = privateKey;
            KeysGenerated = true;
            StatusMessage = "Key pair generated successfully.";

            // Only on success. A failed attempt leaves the fields alone so the user can fix the
            // name or the expiry and try again without retyping.
            ClearPassphrases();
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

    private void ClearPassphrases()
    {
        Passphrase = Array.Empty<char>();
        ConfirmPassphrase = Array.Empty<char>();
        PassphraseCleared?.Invoke(this, EventArgs.Empty);
    }

    [RelayCommand]
    private async Task CopyPublicKeyAsync()
    {
        if (string.IsNullOrEmpty(GeneratedPublicKey)) return;
        await _clipboard.SetTextAsync(GeneratedPublicKey);
        StatusMessage = "Public key copied to the clipboard.";
    }

    [RelayCommand]
    private async Task CopyPrivateKeyAsync()
    {
        if (string.IsNullOrEmpty(GeneratedPrivateKey)) return;
        await _clipboard.SetTextAsync(GeneratedPrivateKey);
        StatusMessage = "Private key copied to the clipboard. Paste it somewhere safe, then clear the clipboard.";
    }

    [RelayCommand]
    private async Task SaveKeysAsync()
    {
        if (!KeysGenerated) return;

        string? folder = await _filePicker.SelectFolderAsync("Select a folder to save the keys in");
        if (folder == null) return;

        try
        {
            string identity = new KeyGenerationOptions { Name = Name, Email = Email }.Identity;
            string safeName = string.Join("_", identity.Split(Path.GetInvalidFileNameChars()));

            string publicPath = Path.Combine(folder, $"{safeName}_public.asc");
            string privatePath = Path.Combine(folder, $"{safeName}_private.asc");

            await File.WriteAllTextAsync(publicPath, GeneratedPublicKey);
            await File.WriteAllTextAsync(privatePath, GeneratedPrivateKey);

            // The private key is landing in a folder the user chose, which on Unix is very likely
            // to be group and world readable by default.
            KeyStoreLocation.RestrictFile(privatePath);

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
            StatusMessage = "Keys imported into the key store.";
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
