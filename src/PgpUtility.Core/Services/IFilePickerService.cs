namespace PgpUtility.Services;

public enum PgpFileType { All, Keys, Encrypted, Signatures, Backups }

public static class PgpFileTypes
{
    public const PgpFileType Keys = PgpFileType.Keys;
    public const PgpFileType Encrypted = PgpFileType.Encrypted;
    public const PgpFileType Signatures = PgpFileType.Signatures;
    public const PgpFileType Backups = PgpFileType.Backups;
}

public interface IFilePickerService
{
    Task<IReadOnlyList<string>> OpenFilesAsync(string title, params PgpFileType[] fileTypes);
    Task<string?> OpenFileAsync(string title, params PgpFileType[] fileTypes);
    Task<string?> SaveFileAsync(string title, string suggestedFileName, params PgpFileType[] fileTypes);
    Task<string?> SelectFolderAsync(string title);
}
