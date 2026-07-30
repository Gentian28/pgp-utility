namespace PgpUtility.Services;

public interface IFileDialogService
{
    string? OpenFile(string title, string filter);
    string[]? OpenFiles(string title, string filter);
    string? SaveFile(string title, string filter, string? defaultFileName = null);
    string? SelectFolder(string title);
}
