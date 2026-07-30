using Avalonia;
using Velopack;

namespace PgpUtility.App;

internal static class Program
{
    // Must stay [STAThread] and must not touch Avalonia before AppMain: the Windows clipboard and
    // the native file dialogs both require a single-threaded apartment.
    [STAThread]
    public static void Main(string[] args)
    {
        // First, before any UI. The installer re-runs the executable with hook arguments during
        // install, update and uninstall, and this is what handles them and exits. Starting
        // Avalonia first would flash a window during a silent install and leave shortcuts
        // unwritten.
        VelopackApp.Build().Run();

        BuildAvaloniaApp().StartWithClassicDesktopLifetime(args);
    }

    // Referenced by name by the Avalonia XAML previewer, so the signature is fixed.
    public static AppBuilder BuildAvaloniaApp()
        => AppBuilder.Configure<App>()
            .UsePlatformDetect()
            .WithInterFont()
            .LogToTrace();
}
