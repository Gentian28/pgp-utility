namespace PgpUtility.Tests;

/// <summary>
/// A scratch directory that deletes itself. Every test that touches the filesystem gets its own,
/// so tests never collide and a failure leaves nothing behind to confuse the next run.
/// </summary>
public sealed class TempWorkspace : IDisposable
{
    public string Root { get; }

    public TempWorkspace()
    {
        // Fully qualified: the Path method below shadows System.IO.Path inside this class.
        Root = System.IO.Path.Combine(
            System.IO.Path.GetTempPath(), "pgputil-tests", Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(Root);
    }

    public string Path(string name) => System.IO.Path.Combine(Root, name);

    /// <summary>Writes <paramref name="bytes"/> to a file in the workspace and returns its path.</summary>
    public string WriteFile(string name, byte[] bytes)
    {
        string path = Path(name);
        File.WriteAllBytes(path, bytes);
        return path;
    }

    public void Dispose()
    {
        // Best effort. A locked file on a failing test is not worth turning into a second failure
        // that masks the first.
        try { Directory.Delete(Root, recursive: true); } catch { }
    }
}
