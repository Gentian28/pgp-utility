using System.Collections.ObjectModel;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using PgpUtility.Models;
using PgpUtility.Services;

namespace PgpUtility.ViewModels;

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
    private readonly OperationRevision _revision = new();

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
        ReportFailure = addLog;
        RefreshKeys();
    }

    partial void OnPassphraseChanging(char[]? oldValue, char[] newValue) => ZeroIfReplaced(oldValue, newValue);

    partial void OnSelectedActionChanged(TextAction value)
    {
        Invalidate();
        ClearPassphrase();
        RefreshKeys();
    }

    partial void OnInputChanged(string value) => Invalidate();
    partial void OnSelectedKeyIdChanged(string? value) => Invalidate();
    private void Invalidate() { _revision.Next(); Result = null; Output = string.Empty; StatusMessage = string.Empty; }
    private void ClearPassphrase() { Passphrase = []; PassphraseCleared?.Invoke(this, EventArgs.Empty); }

    public void RefreshKeys()
    {
        if (IsBusy) return;
        var keys = ReadKeys(_keyStoreService, Invalidate);
        if (keys is null) return;
        string? selected = SelectedKeyId;
        var before = AvailableKeys.FirstOrDefault(k => k.KeyId == selected);
        AvailableKeys.Clear();

        // Decrypt and sign need a secret key. Encrypt and verify work with anyone's public one.
        bool secretRequired = NeedsPassphrase;

        foreach (var key in keys)
        {
            if ((!secretRequired || key.HasPrivateKey) &&
                (SelectedAction != TextAction.Encrypt || key.CanEncrypt) &&
                (SelectedAction != TextAction.Sign || key.CanSign))
                AvailableKeys.Add(key);
        }
        SelectedKeyId = AvailableKeys.Any(k => k.KeyId == selected) ? selected : null;
        if (!SameKeyState(before, AvailableKeys.FirstOrDefault(k => k.KeyId == SelectedKeyId))) Invalidate();
    }

    private bool CanRun() =>
        !string.IsNullOrWhiteSpace(Input) && !string.IsNullOrEmpty(SelectedKeyId);

    [RelayCommand(CanExecute = nameof(CanRun))]
    private async Task RunAsync()
    {
        IsBusy = true;
        Invalidate();
        int revision = _revision.Next();
        TextAction action = SelectedAction;
        string input = Input;
        bool needsSecret = NeedsPassphrase;
        char[] passphrase = (char[])Passphrase.Clone();

        try
        {
            string? keyPath = _keyStoreService.GetKeyFilePath(SelectedKeyId!, privateKey: needsSecret);
            if (keyPath == null)
            {
                StatusMessage = "That key is not in the store any more.";
                return;
            }

            OperationResult? operation = null;
            SignatureVerification? verification = null;
            switch (action)
            {
                case TextAction.Encrypt:
                    operation = await _pgpService.EncryptTextAsync(input, keyPath, isFilePath: true);
                    break;

                case TextAction.Decrypt:
                    operation = await _pgpService.DecryptTextAsync(input, keyPath, isFilePath: true, passphrase);
                    break;

                case TextAction.Sign:
                    operation = await _signatures.SignTextAsync(input, keyPath, isFilePath: true, passphrase);
                    break;

                case TextAction.Verify:
                    verification = await _signatures.VerifyTextAsync(input, keyPath, isFilePath: true);
                    break;
            }
            if (!_revision.IsCurrent(revision)) return;
            if (operation is not null) await ShowAsync(operation);
            if (verification is not null) { Result = verification; StatusMessage = verification.Message; _addLog(verification.Message); }
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
            if (needsSecret) ClearPassphrase();
            IsBusy = false;
            RefreshKeys();
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
    private Task PasteAsync() => GuardAsync(async () =>
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
    });

    [RelayCommand]
    private Task CopyOutputAsync() => GuardAsync(async () =>
    {
        if (string.IsNullOrEmpty(Output)) return;
        await _clipboard.SetTextAsync(Output);
        StatusMessage = "Copied to the clipboard.";
    });

    [RelayCommand]
    private void Clear()
    {
        Invalidate();
        ClearPassphrase();
        Input = string.Empty;
        Output = string.Empty;
        Result = null;
        StatusMessage = string.Empty;
    }
}
