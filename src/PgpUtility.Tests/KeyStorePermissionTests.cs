using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using PgpUtility.Services;

namespace PgpUtility.Tests;

/// <summary>
/// A world-readable private key directory is a real vulnerability, and Windows hides it during
/// development because %APPDATA% already inherits a restrictive ACL. These tests only mean
/// anything on the platforms where the problem exists, which is why CI runs on all three.
/// </summary>
[Collection(KeyCollection.Name)]
public class KeyStorePermissionTests
{
    private readonly GeneratedKeys _keys;

    public KeyStorePermissionTests(GeneratedKeys keys) => _keys = keys;

    private static bool OnUnix => !OperatingSystem.IsWindows();

    [SkippableFact]
    // Tells the platform analyzer what Skip.IfNot cannot: this body never runs on Windows.
    [UnsupportedOSPlatform("windows")]
    public void The_key_directory_is_owner_only()
    {
        Skip.IfNot(OnUnix, "file modes are a Unix concept; Windows uses inherited ACLs");

        using var work = new TempWorkspace();
        string directory = work.Path("keys");
        _ = new KeyStoreService(_keys.Service, directory);

        UnixFileMode mode = File.GetUnixFileMode(directory);

        mode.Should().Be(UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
        mode.Should().NotHaveFlag(UnixFileMode.GroupRead);
        mode.Should().NotHaveFlag(UnixFileMode.OtherRead);
    }

    [SkippableFact]
    // Tells the platform analyzer what Skip.IfNot cannot: this body never runs on Windows.
    [UnsupportedOSPlatform("windows")]
    public async Task A_stored_private_key_is_owner_only()
    {
        Skip.IfNot(OnUnix, "file modes are a Unix concept; Windows uses inherited ACLs");

        using var work = new TempWorkspace();
        var store = new KeyStoreService(_keys.Service, work.Path("keys"));

        var imported = await store.ImportKeyFromStringAsync(_keys.Ed25519Private, isPrivate: true);
        string? path = store.GetKeyFilePath(imported.KeyId, privateKey: true);
        path.Should().NotBeNull();

        File.GetUnixFileMode(path!).Should().Be(UnixFileMode.UserRead | UnixFileMode.UserWrite);
    }

    [SkippableFact]
    // Tells the platform analyzer what Skip.IfNot cannot: this body never runs on Windows.
    [UnsupportedOSPlatform("windows")]
    public async Task A_private_key_copied_in_from_a_world_readable_file_is_locked_down()
    {
        Skip.IfNot(OnUnix, "file modes are a Unix concept; Windows uses inherited ACLs");

        // A copy carries the source's permissions. Importing a key someone left at 0644 must not
        // leave it at 0644 inside the store.
        using var work = new TempWorkspace();
        var store = new KeyStoreService(_keys.Service, work.Path("keys"));

        string loose = work.Path("loose-sec.asc");
        await File.WriteAllTextAsync(loose, _keys.Ed25519Private);
        File.SetUnixFileMode(loose,
            UnixFileMode.UserRead | UnixFileMode.UserWrite |
            UnixFileMode.GroupRead | UnixFileMode.OtherRead);

        var imported = await store.ImportPrivateKeyAsync(loose);
        string? path = store.GetKeyFilePath(imported.KeyId, privateKey: true);

        File.GetUnixFileMode(path!).Should().Be(UnixFileMode.UserRead | UnixFileMode.UserWrite);
    }

    [SkippableFact]
    // Tells the platform analyzer what Skip.IfNot cannot: this body never runs on Windows.
    [UnsupportedOSPlatform("windows")]
    public async Task An_exported_private_key_is_owner_only()
    {
        Skip.IfNot(OnUnix, "file modes are a Unix concept; Windows uses inherited ACLs");

        using var work = new TempWorkspace();
        var store = new KeyStoreService(_keys.Service, work.Path("keys"));

        var imported = await store.ImportKeyFromStringAsync(_keys.Ed25519Private, isPrivate: true);
        string exported = work.Path("exported-sec.asc");
        await store.ExportKeyAsync(imported.KeyId, exported, exportPrivate: true);

        File.GetUnixFileMode(exported).Should().Be(UnixFileMode.UserRead | UnixFileMode.UserWrite);
    }

    [Fact]
    public void An_override_wins_over_the_platform_default()
    {
        string? original = Environment.GetEnvironmentVariable(KeyStoreLocation.OverrideVariable);
        try
        {
            Environment.SetEnvironmentVariable(KeyStoreLocation.OverrideVariable, "/tmp/elsewhere");
            KeyStoreLocation.Default().Should().Be("/tmp/elsewhere");
        }
        finally
        {
            Environment.SetEnvironmentVariable(KeyStoreLocation.OverrideVariable, original);
        }
    }

    [Fact]
    public void The_default_location_follows_the_platform_convention()
    {
        // Guard: an override leaking in from another test would make this assert nothing.
        Environment.GetEnvironmentVariable(KeyStoreLocation.OverrideVariable)
            .Should().BeNullOrEmpty();

        string path = KeyStoreLocation.Default();

        if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
        {
            path.Should().EndWith(Path.Combine("PgpUtility", "Keys"));
            path.Should().StartWith(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData));
        }
        else if (RuntimeInformation.IsOSPlatform(OSPlatform.OSX))
        {
            path.Should().Contain(Path.Combine("Library", "Application Support", "PgpUtility"));
            path.Should().NotContain(".config", "that is a Linux convention, not a macOS one");
        }
        else
        {
            path.Should().EndWith(Path.Combine("pgputility", "keys"));
        }
    }

    [SkippableFact]
    public void The_linux_location_honours_XDG_DATA_HOME()
    {
        Skip.If(OperatingSystem.IsWindows() || OperatingSystem.IsMacOS(), "XDG applies to Linux");

        string? original = Environment.GetEnvironmentVariable("XDG_DATA_HOME");
        try
        {
            Environment.SetEnvironmentVariable("XDG_DATA_HOME", "/tmp/xdg-probe");
            KeyStoreLocation.Default().Should().Be(Path.Combine("/tmp/xdg-probe", "pgputility", "keys"));
        }
        finally
        {
            Environment.SetEnvironmentVariable("XDG_DATA_HOME", original);
        }
    }
}
