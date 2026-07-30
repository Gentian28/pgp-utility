using Avalonia.Controls;
using Avalonia.Input.Platform;

namespace PgpUtility.App.Services;

/// <summary>
/// Clipboard access, async because every platform's clipboard is.
/// </summary>
/// <remarks>
/// An interface rather than a direct call so the view models keep no reference to a window.
/// The WPF version called System.Windows.Clipboard straight from the view model, which is what
/// made those view models untestable and unportable.
/// </remarks>
public interface IClipboardService
{
    Task SetTextAsync(string text);

    Task<string?> GetTextAsync();
}

public sealed class ClipboardService : IClipboardService
{
    private readonly Func<TopLevel?> _topLevel;

    public ClipboardService(Func<TopLevel?> topLevel) => _topLevel = topLevel;

    public async Task SetTextAsync(string text)
    {
        if (_topLevel()?.Clipboard is { } clipboard)
            await clipboard.SetTextAsync(text);
    }

    public async Task<string?> GetTextAsync()
    {
        // TryGetTextAsync rather than GetTextAsync: the latter is obsolete because it throws when
        // the clipboard holds something that is not text, which is a normal thing for it to hold.
        if (_topLevel()?.Clipboard is { } clipboard)
            return await clipboard.TryGetTextAsync();
        return null;
    }
}
