using CommunityToolkit.Mvvm.ComponentModel;

namespace PgpUtility.ViewModels;

public partial class ViewModelBase : ObservableObject
{
    protected Action<string>? ReportFailure { get; set; }

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
