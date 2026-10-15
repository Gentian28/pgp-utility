using PgpUtility.Services;
using Avalonia.Platform.Storage;

namespace PgpUtility.App.Services;

/// <summary>The file type filters this app offers, in one place so the tabs agree with each other.</summary>
internal static class NativeFileTypes
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

    public static FilePickerFileType Backups { get; } = new("PGP Utility backup")
    { Patterns = ["*.zip"], AppleUniformTypeIdentifiers = ["public.zip-archive"], MimeTypes = ["application/zip"] };

    public static FilePickerFileType Convert(PgpFileType type) => type switch
    {
        PgpFileType.Keys => Keys, PgpFileType.Encrypted => Encrypted,
        PgpFileType.Signatures => Signatures, PgpFileType.Backups => Backups,
        _ => FilePickerFileTypes.All
    };
}
