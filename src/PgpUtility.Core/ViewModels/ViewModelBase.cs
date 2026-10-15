using CommunityToolkit.Mvvm.ComponentModel;
using PgpUtility.Models;
using PgpUtility.Services;
using System.Collections.ObjectModel;

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

    protected static void SynchronizeKeyChoices(ObservableCollection<PgpKeyInfo> choices, IEnumerable<PgpKeyInfo> keys)
    {
        var desired = keys.ToList();
        static string Identity(PgpKeyInfo key) => string.IsNullOrEmpty(key.Fingerprint) ? key.KeyId : key.Fingerprint;
        static bool SameChoice(PgpKeyInfo before, PgpKeyInfo after) => SameKeyState(before, after) &&
            (before.KeyId, before.UserId, before.Algorithm, before.KeySize, before.CreationDate, before.PublicKeyFile, before.PrivateKeyFile) ==
            (after.KeyId, after.UserId, after.Algorithm, after.KeySize, after.CreationDate, after.PublicKeyFile, after.PrivateKeyFile);

        // Resetting an otherwise unchanged list drops the desktop picker's visual selection.
        // Retain unchanged instances and update only identities or metadata that actually changed.
        for (int index = choices.Count - 1; index >= 0; index--)
            if (!desired.Any(key => Identity(key) == Identity(choices[index]))) choices.RemoveAt(index);
        for (int index = 0; index < desired.Count; index++)
        {
            int existing = -1;
            for (int candidate = index; candidate < choices.Count; candidate++)
                if (Identity(choices[candidate]) == Identity(desired[index])) { existing = candidate; break; }
            if (existing < 0) choices.Insert(index, desired[index]);
            else
            {
                if (existing != index) choices.Move(existing, index);
                if (!SameChoice(choices[index], desired[index])) choices[index] = desired[index];
            }
        }
    }

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
