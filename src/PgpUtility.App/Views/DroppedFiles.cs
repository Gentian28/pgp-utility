using Avalonia.Input;
using Avalonia.Platform.Storage;

namespace PgpUtility.App.Views;

/// <summary>
/// Turns a drop into a list of paths on disk.
/// </summary>
/// <remarks>
/// Shared because two views accept drops and the awkward parts are identical: a drop carries
/// storage items rather than paths, a folder can be dropped as easily as a file, and an item is
/// not guaranteed to have a local path at all. Everything below the UI works in paths, so items
/// without one are dropped rather than turned into a broken path string.
///
/// Uses DataTransfer rather than the older Data property, which Avalonia 11.3 deprecated.
/// </remarks>
internal static class DroppedFiles
{
    /// <summary>True when the drop is carrying files, so the view can show a copy cursor.</summary>
    internal static bool HasFiles(DragEventArgs e) =>
        e.DataTransfer?.Contains(DataFormat.File) == true;

    internal static IReadOnlyList<string> PathsFrom(DragEventArgs e)
    {
        IReadOnlyList<IStorageItem>? items = e.DataTransfer?.TryGetFiles();
        if (items is null) return [];

        var paths = new List<string>();
        foreach (IStorageItem item in items)
        {
            // Only files. Dropping a folder on an encrypt tab most likely means "everything in
            // here", which is a different feature, and silently encrypting nothing would be worse
            // than ignoring the drop.
            if (item is not IStorageFile file) continue;

            if (file.TryGetLocalPath() is { Length: > 0 } path)
                paths.Add(path);
        }

        return paths;
    }
}
