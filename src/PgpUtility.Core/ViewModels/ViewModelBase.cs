using CommunityToolkit.Mvvm.ComponentModel;
using PgpUtility.Models;
using PgpUtility.Services;

namespace PgpUtility.ViewModels;

public partial class ViewModelBase : ObservableObject
{
    protected Action<string>? ReportFailure { get; set; }

    protected IReadOnlyList<PgpKeyInfo>? ReadKeys(IKeyStoreService store, Action? invalidate = null)
    {
        try { return store.GetAllKeys(); }
        catch (Exception ex)
        {
            invalidate?.Invoke();
            StatusMessage = $"Keys could not be refreshed: {ex.Message}";
            ReportFailure?.Invoke(StatusMessage);
            return null;
        }
    }

    protected static bool SameKeyState(PgpKeyInfo? before, PgpKeyInfo? after) =>
        (before?.Fingerprint, before?.ExpirationDate, before?.IsRevoked, before?.HasPrivateKey, before?.CanEncrypt, before?.CanSign) ==
        (after?.Fingerprint, after?.ExpirationDate, after?.IsRevoked, after?.HasPrivateKey, after?.CanEncrypt, after?.CanSign);

    protected async Task GuardAsync(Func<Task> action)
    {
        try { await action(); }
        catch (OperationCanceledException) { StatusMessage = "Operation cancelled."; }
        catch (Exception ex)
        {
            StatusMessage = $"The operation could not be completed: {ex.Message}";
            ReportFailure?.Invoke(StatusMessage);
        }
    }
    [ObservableProperty]
    private bool _isBusy;

    [ObservableProperty]
    private string _statusMessage = string.Empty;

    /// <summary>
    /// Zeroes a passphrase array before it is replaced, unless it is the same array coming back.
    /// </summary>
    /// <remarks>
    /// Shared because every view model holding a passphrase needs it in its OnChanging partial,
    /// and a copy that forgot the reference check would zero the value it was just handed.
    /// </remarks>
    private protected static void ZeroIfReplaced(char[]? oldValue, char[] newValue)
    {
        if (oldValue is not null && !ReferenceEquals(oldValue, newValue))
            Array.Clear(oldValue);
    }
}
