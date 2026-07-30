using Avalonia.Platform.Storage;

namespace PgpUtility.App.Services;

/// <summary>
/// File and folder pickers.
/// </summary>
/// <remarks>
/// Async all the way down, unlike the Microsoft.Win32 dialogs this replaces. Avalonia's
/// IStorageProvider is async because a browser or a sandboxed platform cannot block the UI thread
/// waiting for a picker, so every calling command became async too. That is a real change in
/// shape, not a wrapper detail, which is why the interface admits it rather than hiding it behind
/// a synchronous facade.
/// </remarks>
public interface IFilePickerService
{
    Task<IReadOnlyList<string>> OpenFilesAsync(string title, params FilePickerFileType[] fileTypes);

    Task<string?> OpenFileAsync(string title, params FilePickerFileType[] fileTypes);

    Task<string?> SaveFileAsync(string title, string suggestedFileName, params FilePickerFileType[] fileTypes);

    Task<string?> SelectFolderAsync(string title);
}

/// <summary>The file type filters this app offers, in one place so the tabs agree with each other.</summary>
public static class PgpFileTypes
{
    public static FilePickerFileType Keys { get; } = new("OpenPGP keys")
    {
        Patterns = ["*.asc", "*.gpg", "*.pgp", "*.pub", "*.sec", "*.key"],
        // Set so macOS shows the right files: it filters by UTType, not by glob, and without this
        // every key file appears greyed out and unselectable.
        AppleUniformTypeIdentifiers = ["public.data"],
        MimeTypes = ["application/pgp-keys"]
    };

    public static FilePickerFileType Encrypted { get; } = new("Encrypted files")
    {
        Patterns = ["*.pgp", "*.gpg", "*.asc"],
        AppleUniformTypeIdentifiers = ["public.data"],
        MimeTypes = ["application/pgp-encrypted"]
    };

    public static FilePickerFileType Signatures { get; } = new("Signatures")
    {
        Patterns = ["*.sig", "*.asc"],
        AppleUniformTypeIdentifiers = ["public.data"],
        MimeTypes = ["application/pgp-signature"]
    };

    public static FilePickerFileType All => FilePickerFileTypes.All;
}
