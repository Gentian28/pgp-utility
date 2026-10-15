using System.Security.AccessControl;
using System.Security.Principal;
using System.Text;

namespace PgpUtility.Services;

/// <summary>Owns a unique staging file. Failure cleanup never touches the destination.</summary>
public sealed class FileTransaction : IDisposable
{
    private readonly string _destination;
    private readonly string _stagingPath;
    private bool _committed;
    public FileStream Stream { get; }

    public FileTransaction(string destination)
    {
        _destination = Path.GetFullPath(destination);
        _stagingPath = Path.Combine(Path.GetDirectoryName(_destination)!, ".pgputility-" + Guid.NewGuid().ToString("N") + ".partial");
        Stream = CreatePrivate(_stagingPath);
    }

    public void Commit(bool replaceExisting = false, CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        if (Stream.CanWrite)
        {
            Stream.Flush(flushToDisk: true);
            Stream.Dispose();
        }
        else
        {
            // Armor writers may close the stream they wrap before the commit boundary.
            using var flush = new FileStream(_stagingPath, FileMode.Open, FileAccess.Write, FileShare.None);
            flush.Flush(flushToDisk: true);
        }
        cancellationToken.ThrowIfCancellationRequested();
        File.Move(_stagingPath, _destination, replaceExisting);
        _committed = true;
    }

    public static void RequireNewOutput(string input, string output)
    {
        if (string.Equals(Path.GetFullPath(input), Path.GetFullPath(output),
            OperatingSystem.IsWindows() ? StringComparison.OrdinalIgnoreCase : StringComparison.Ordinal))
            throw new IOException("The input and output must be different files.");
        if (File.Exists(output) || Directory.Exists(output))
            throw new IOException("The output already exists. Choose a different name or folder to preserve the existing file.");
    }

    public static async Task WriteTextAsync(string path, string text, bool replaceExisting = false,
        CancellationToken cancellationToken = default)
    {
        using var transaction = new FileTransaction(path);
        await transaction.Stream.WriteAsync(Encoding.UTF8.GetBytes(text), cancellationToken);
        transaction.Commit(replaceExisting, cancellationToken);
    }

    public static async Task CopyAsync(string source, string destination, bool replaceExisting = false,
        CancellationToken cancellationToken = default)
    {
        using var input = File.OpenRead(source);
        using var transaction = new FileTransaction(destination);
        await input.CopyToAsync(transaction.Stream, cancellationToken);
        transaction.Commit(replaceExisting, cancellationToken);
    }

    internal static FileStream CreatePrivate(string path)
    {
        if (OperatingSystem.IsWindows())
        {
            var identity = WindowsIdentity.GetCurrent().User ?? throw new IOException("Cannot determine the file owner.");
            var security = new FileSecurity();
            security.SetOwner(identity);
            security.SetAccessRuleProtection(isProtected: true, preserveInheritance: false);
            security.AddAccessRule(new FileSystemAccessRule(identity, FileSystemRights.FullControl, AccessControlType.Allow));
            return new FileInfo(path).Create(FileMode.CreateNew, FileSystemRights.FullControl, FileShare.None,
                65536, FileOptions.None, security);
        }
        return new FileStream(path, new FileStreamOptions
        {
            Mode = FileMode.CreateNew, Access = FileAccess.ReadWrite, Share = FileShare.None,
            BufferSize = 65536, UnixCreateMode = UnixFileMode.UserRead | UnixFileMode.UserWrite
        });
    }

    public void Dispose()
    {
        Stream.Dispose();
        if (_committed) return;
        try { File.Delete(_stagingPath); } catch (IOException) { } catch (UnauthorizedAccessException) { }
    }
}
