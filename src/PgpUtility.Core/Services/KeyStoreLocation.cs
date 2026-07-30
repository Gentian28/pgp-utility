using System.Runtime.InteropServices;

namespace PgpUtility.Services;

/// <summary>
/// Decides where the key store lives and locks its permissions down.
/// </summary>
public static class KeyStoreLocation
{
    /// <summary>
    /// The per-user key store directory, following each platform's own convention rather than
    /// imposing one platform's on the others.
    /// </summary>
    /// <remarks>
    /// Windows: <c>%APPDATA%\PgpUtility\Keys</c>.
    /// macOS: <c>~/Library/Application Support/PgpUtility/Keys</c>, which is where a Mac user
    /// expects application data and not where .NET's ApplicationData maps to.
    /// Linux: <c>$XDG_DATA_HOME/pgputility/keys</c>, falling back to
    /// <c>~/.local/share/pgputility/keys</c>. Lower case, because that is the convention there.
    /// </remarks>
    public static string Default()
    {
        if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
        {
            return Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
                "PgpUtility", "Keys");
        }

        string home = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);

        if (RuntimeInformation.IsOSPlatform(OSPlatform.OSX))
        {
            // .NET maps SpecialFolder.ApplicationData to ~/.config on macOS, which is a Linux
            // convention that Mac users do not expect. Named explicitly instead.
            return Path.Combine(home, "Library", "Application Support", "PgpUtility", "Keys");
        }

        string dataHome = Environment.GetEnvironmentVariable("XDG_DATA_HOME") is { Length: > 0 } xdg
            ? xdg
            : Path.Combine(home, ".local", "share");

        return Path.Combine(dataHome, "pgputility", "keys");
    }

    /// <summary>
    /// Creates the directory if it is missing and restricts it to the owner.
    /// </summary>
    /// <remarks>
    /// On Unix the directory becomes 0700. Anything less means every other account on the machine
    /// can read stored private keys, which is a real vulnerability and not a hardening nicety.
    /// It is easy to miss during development because Windows inherits a restrictive ACL from the
    /// user profile and shows no symptom.
    ///
    /// No-op on Windows: <c>%APPDATA%</c> already inherits an ACL granting only the owner and
    /// administrators, and hand-writing ACLs here would more likely break inheritance than
    /// improve on it.
    /// </remarks>
    public static void CreateSecureDirectory(string path)
    {
        Directory.CreateDirectory(path);
        RestrictDirectory(path);
    }

    /// <summary>
    /// Restricts a key file to the owner: 0600 on Unix, no-op on Windows.
    /// </summary>
    /// <remarks>
    /// Applied to every file written into the store, not just at creation. A file copied in from
    /// elsewhere arrives with the source's permissions, so inheriting the directory mode is not
    /// something to rely on.
    /// </remarks>
    public static void RestrictFile(string path)
    {
        if (OperatingSystem.IsWindows() || !File.Exists(path))
            return;

        File.SetUnixFileMode(path, UnixFileMode.UserRead | UnixFileMode.UserWrite);
    }

    private static void RestrictDirectory(string path)
    {
        if (OperatingSystem.IsWindows())
            return;

        File.SetUnixFileMode(path,
            UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
    }
}
