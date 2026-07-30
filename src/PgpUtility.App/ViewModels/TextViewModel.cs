using System.Collections.ObjectModel;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using PgpUtility.App.Services;
using PgpUtility.Models;
using PgpUtility.Services;

namespace PgpUtility.App.ViewModels;

/// <summary>
/// Text in, text out.
/// </summary>
/// <remarks>
/// Most real PGP traffic is a block of text in an email or a message, not a file on disk, and a
/// file-only tool makes people round-trip through a text editor and a temporary file to do the
/// most ordinary thing there is.
/// </remarks>
public partial class TextViewModel : ViewModelBase
{
    private readonly IPgpService _pgpService;
    private readonly IPgpSignatureService _signatures;
    private readonly IKeyStoreService _keyStoreService;
    private readonly IClipboardService _clipboard;
    private readonly Action<string> _addLog;

    public event EventHandler? PassphraseCleared;

    public enum TextAction { Encrypt, Decrypt, Sign, Verify }

    [ObservableProperty]
    [NotifyCanExecuteChangedFor(nameof(RunCommand))]
    [NotifyPropertyChangedFor(nameof(NeedsPassphrase))]
    [NotifyPropertyChangedFor(nameof(ActionLabel))]
    private TextAction _selectedAction = TextAction.Encrypt;

    [ObservableProperty]
    [NotifyCanExecuteChangedFor(nameof(RunCommand))]
    private string _input = string.Empty;

    [ObservableProperty]
    private string _output = string.Empty;

    [ObservableProperty]
    [NotifyCanExecuteChangedFor(nameof(RunCommand))]
    private string? _selectedKeyId;

    [ObservableProperty]
    private char[] _passphrase = Array.Empty<char>();

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(HasResult))]
    private SignatureVerification? _result;

    public ObservableCollection<PgpKeyInfo> AvailableKeys { get; } = new();

    public IReadOnlyList<TextAction> Actions { get; } =
        [TextAction.Encrypt, TextAction.Decrypt, TextAction.Sign, TextAction.Verify];

    /// <summary>Decrypting and signing both unlock a secret key; the other two do not.</summary>
    public bool NeedsPassphrase =>
        SelectedAction is TextAction.Decrypt or TextAction.Sign;

    public bool HasResult => Result != null;

    public string ActionLabel => SelectedAction.ToString();

    public TextViewModel(
        IPgpService pgpService,
        IPgpSignatureService signatures,
        IKeyStoreService keyStoreService,
        IClipboardService clipboard,
        Action<string> addLog)
    {
        _pgpService = pgpService;
        _signatures = signatures;
        _keyStoreService = keyStoreService;
        _clipboard = clipboard;
        _addLog = addLog;
        RefreshKeys();
    }

    partial void OnPassphraseChanging(char[]? oldValue, char[] newValue) => ZeroIfReplaced(oldValue, newValue);

    partial void OnSelectedActionChanged(TextAction value)
    {
        Result = null;
        RefreshKeys();
    }

    public void RefreshKeys()
    {
        AvailableKeys.Clear();

        // Decrypt and sign need a secret key. Encrypt and verify work with anyone's public one.
        bool secretRequired = NeedsPassphrase;

        foreach (var key in _keyStoreService.GetAllKeys())
        {
            if (!secretRequired || key.HasPrivateKey)
                AvailableKeys.Add(key);
        }
    }

    private bool CanRun() =>
        !string.IsNullOrWhiteSpace(Input) && !string.IsNullOrEmpty(SelectedKeyId);

    [RelayCommand(CanExecute = nameof(CanRun))]
    private async Task RunAsync()
    {
        IsBusy = true;
        Result = null;

        try
        {
            string? keyPath = _keyStoreService.GetKeyFilePath(SelectedKeyId!, privateKey: NeedsPassphrase);
            if (keyPath == null)
            {
                StatusMessage = "That key is not in the store any more.";
                return;
            }

            switch (SelectedAction)
            {
                case TextAction.Encrypt:
                    await ShowAsync(await _pgpService.EncryptTextAsync(Input, keyPath, isFilePath: true));
                    break;

                case TextAction.Decrypt:
                    await ShowAsync(await _pgpService.DecryptTextAsync(Input, keyPath, isFilePath: true, Passphrase));
                    break;

                case TextAction.Sign:
                    await ShowAsync(await _signatures.SignTextAsync(Input, keyPath, isFilePath: true, Passphrase));
                    break;

                case TextAction.Verify:
                    Result = await _signatures.VerifyTextAsync(Input, keyPath, isFilePath: true);
                    StatusMessage = Result.Message;
                    _addLog(Result.Message);
                    break;
            }
        }
        catch (Exception ex)
        {
            StatusMessage = $"Error: {ex.Message}";
            _addLog(StatusMessage);
        }
        finally
        {
            if (NeedsPassphrase)
            {
                Passphrase = Array.Empty<char>();
                PassphraseCleared?.Invoke(this, EventArgs.Empty);
            }
            IsBusy = false;
        }
    }

    private Task ShowAsync(OperationResult result)
    {
        // Output is only ever set from a successful result. Leaving the previous output on screen
        // after a failure would let someone copy a stale block believing it is the new one.
        Output = result.Success ? result.Payload ?? string.Empty : string.Empty;
        StatusMessage = result.Warning ?? result.Message;
        _addLog(result.Message);
        if (result.Warning != null) _addLog(result.Warning);
        return Task.CompletedTask;
    }

    [RelayCommand]
    private async Task PasteAsync()
    {
        string? text = await _clipboard.GetTextAsync();
        if (string.IsNullOrEmpty(text))
        {
            StatusMessage = "The clipboard does not contain any text.";
            return;
        }

        Input = text;

        // Pick the obvious action from what was pasted. A PGP MESSAGE is there to be decrypted
        // and a SIGNED MESSAGE to be verified, so making the user say so again is busywork.
        if (text.Contains("BEGIN PGP SIGNED MESSAGE", StringComparison.Ordinal))
            SelectedAction = TextAction.Verify;
        else if (text.Contains("BEGIN PGP MESSAGE", StringComparison.Ordinal))
            SelectedAction = TextAction.Decrypt;
    }

    [RelayCommand]
    private async Task CopyOutputAsync()
    {
        if (string.IsNullOrEmpty(Output)) return;
        await _clipboard.SetTextAsync(Output);
        StatusMessage = "Copied to the clipboard.";
    }

    [RelayCommand]
    private void Clear()
    {
        Input = string.Empty;
        Output = string.Empty;
        Result = null;
        StatusMessage = string.Empty;
    }
}
