using PgpUtility.Services;
using Avalonia.Controls;
using Avalonia.Input.Platform;

namespace PgpUtility.App.Services;

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
