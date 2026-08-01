using Avalonia;
using Avalonia.Styling;
using PgpUtility.Services;

namespace PgpUtility.App.Services;

/// <summary>
/// Applies the light or dark theme and remembers the choice between runs.
/// </summary>
/// <remarks>
/// The choice is stored as a single word in a <c>theme</c> file next to the key store directory,
/// so it follows the same per-platform convention without inventing a second location, and the
/// <c>PGPUTILITY_KEY_STORE</c> override isolates it the same way it isolates keys. It is one word
/// of UI state, not key material, so none of the store's permission handling applies.
/// </remarks>
public sealed class ThemeService
{
    /// <summary>Index into the theme choices: 0 follows the system, 1 light, 2 dark.</summary>
    private static readonly ThemeVariant[] Variants =
    {
        ThemeVariant.Default,
        ThemeVariant.Light,
        ThemeVariant.Dark,
    };

    private static readonly string[] Names = { "system", "light", "dark" };

    private static string SettingsPath()
    {
        string store = KeyStoreLocation.Default();
        string? parent = Path.GetDirectoryName(store);
        return Path.Combine(string.IsNullOrEmpty(parent) ? store : parent, "theme");
    }

    public int LoadIndex()
    {
        try
        {
            string name = File.ReadAllText(SettingsPath()).Trim();
            int index = Array.IndexOf(Names, name);
            return index >= 0 ? index : 0;
        }
        catch (IOException)
        {
            return 0;
        }
        catch (UnauthorizedAccessException)
        {
            return 0;
        }
    }

    public void Apply(int index)
    {
        if (Application.Current is { } app && index >= 0 && index < Variants.Length)
            app.RequestedThemeVariant = Variants[index];
    }

    /// <summary>
    /// Persists the choice. A failure is swallowed: the theme has already switched on screen, and
    /// the worst outcome of not writing is that the next run starts on the system theme.
    /// </summary>
    public void Save(int index)
    {
        if (index < 0 || index >= Names.Length)
            return;

        try
        {
            string path = SettingsPath();
            Directory.CreateDirectory(Path.GetDirectoryName(path)!);
            File.WriteAllText(path, Names[index]);
        }
        catch (IOException)
        {
        }
        catch (UnauthorizedAccessException)
        {
        }
    }
}
