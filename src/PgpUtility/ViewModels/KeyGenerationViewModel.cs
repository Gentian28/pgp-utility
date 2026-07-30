using System.IO;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using PgpUtility.Models;
using PgpUtility.Services;

namespace PgpUtility.ViewModels;

/// <summary>
/// One entry in the algorithm dropdown. Wraps the enum so the list can carry a label without the
/// view having to know how to spell each algorithm.
/// </summary>
public sealed record AlgorithmChoice(PgpKeyAlgorithm Value, string Display);

public partial class KeyGenerationViewModel : ViewModelBase
{
    private readonly IPgpService _pgpService;
    private readonly IKeyStoreService _keyStoreService;
    private readonly Action<string> _addLog;

    /// <summary>
    /// Raised once the passphrase has been used and zeroed, so the view can empty its password
    /// boxes. Without it the fields would still show dots for a passphrase this view model no
    /// longer holds, and the next Generate would fail on an empty array.
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
    private DateTime _expirationDate = DateTime.Now.AddYears(1);

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
        Action<string> addLog)
    {
        _pgpService = pgpService;
        _keyStoreService = keyStoreService;
        _addLog = addLog;
    }

    // Zero whatever the field held before it is replaced, so a passphrase does not accumulate one
    // abandoned copy per keystroke.
    partial void OnPassphraseChanging(char[]? oldValue, char[] newValue) => ZeroIfReplaced(oldValue, newValue);

    partial void OnConfirmPassphraseChanging(char[]? oldValue, char[] newValue) => ZeroIfReplaced(oldValue, newValue);

    private static void ZeroIfReplaced(char[]? oldValue, char[] newValue)
    {
        if (oldValue is not null && !ReferenceEquals(oldValue, newValue))
            Array.Clear(oldValue);
    }

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
                ExpirationDate = HasExpiration ? ExpirationDate : null
            };

            var (publicKey, privateKey) = await _pgpService.GenerateKeyPairAsync(options, progress);
            GeneratedPublicKey = publicKey;
            GeneratedPrivateKey = privateKey;
            KeysGenerated = true;
            StatusMessage = "Key pair generated successfully.";

            // Only on success. A failed attempt leaves the fields alone so the user can fix the
            // name or the expiry date and try again without retyping.
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
