using Avalonia.Controls;
using Avalonia.Platform.Storage;

namespace PgpUtility.App.Services;

/// <summary>
/// <see cref="IFilePickerService"/> on top of Avalonia's <see cref="IStorageProvider"/>.
/// </summary>
public sealed class StorageFilePickerService : IFilePickerService
{
    private readonly Func<TopLevel?> _topLevel;

    /// <param name="topLevel">
    /// Resolved per call rather than captured. IStorageProvider hangs off the window, and the
    /// window does not exist yet when the view models are constructed.
    /// </param>
    public StorageFilePickerService(Func<TopLevel?> topLevel) => _topLevel = topLevel;

    public async Task<IReadOnlyList<string>> OpenFilesAsync(string title, params FilePickerFileType[] fileTypes)
    {
        IStorageProvider? storage = _topLevel()?.StorageProvider;
        if (storage is null) return [];

        var files = await storage.OpenFilePickerAsync(new FilePickerOpenOptions
        {
            Title = title,
            AllowMultiple = true,
            FileTypeFilter = Filters(fileTypes)
        });

        return files.Select(LocalPath).OfType<string>().ToList();
    }

    public async Task<string?> OpenFileAsync(string title, params FilePickerFileType[] fileTypes)
    {
        IStorageProvider? storage = _topLevel()?.StorageProvider;
        if (storage is null) return null;

        var files = await storage.OpenFilePickerAsync(new FilePickerOpenOptions
        {
            Title = title,
            AllowMultiple = false,
            FileTypeFilter = Filters(fileTypes)
        });

        return files.Count > 0 ? LocalPath(files[0]) : null;
    }

    public async Task<string?> SaveFileAsync(string title, string suggestedFileName, params FilePickerFileType[] fileTypes)
    {
        IStorageProvider? storage = _topLevel()?.StorageProvider;
        if (storage is null) return null;

        var file = await storage.SaveFilePickerAsync(new FilePickerSaveOptions
        {
            Title = title,
            SuggestedFileName = suggestedFileName,
            FileTypeChoices = Filters(fileTypes)
        });

        return file is null ? null : LocalPath(file);
    }

    public async Task<string?> SelectFolderAsync(string title)
    {
        IStorageProvider? storage = _topLevel()?.StorageProvider;
        if (storage is null) return null;

        var folders = await storage.OpenFolderPickerAsync(new FolderPickerOpenOptions
        {
            Title = title,
            AllowMultiple = false
        });

        return folders.Count > 0 ? LocalPath(folders[0]) : null;
    }

    private static List<FilePickerFileType>? Filters(FilePickerFileType[] fileTypes) =>
        fileTypes.Length == 0 ? null : [.. fileTypes, FilePickerFileTypes.All];

    /// <summary>
    /// The real path on disk, or null if the item has none.
    /// </summary>
    /// <remarks>
    /// A storage item is not guaranteed to be a file: it can be a content URI on a sandboxed
    /// platform. Everything below this layer works in paths because BouncyCastle streams from
    /// disk, so an item without one is dropped rather than turned into a broken path string.
    /// </remarks>
    private static string? LocalPath(IStorageItem item) =>
        item.TryGetLocalPath() is { Length: > 0 } path ? path : null;
}
