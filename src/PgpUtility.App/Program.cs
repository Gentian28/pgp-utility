using Avalonia;

namespace PgpUtility.App;

internal static class Program
{
    // Must stay [STAThread] and must not touch Avalonia before AppMain: the Windows clipboard and
    // the native file dialogs both require a single-threaded apartment.
    [STAThread]
    public static void Main(string[] args) => BuildAvaloniaApp()
        .StartWithClassicDesktopLifetime(args);

    // Referenced by name by the Avalonia XAML previewer, so the signature is fixed.
    public static AppBuilder BuildAvaloniaApp()
        => AppBuilder.Configure<App>()
            .UsePlatformDetect()
            .WithInterFont()
            .LogToTrace();
}
