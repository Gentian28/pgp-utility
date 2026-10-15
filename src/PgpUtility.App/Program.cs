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
        if (!string.IsNullOrWhiteSpace(Environment.GetEnvironmentVariable("PGPUTILITY_STARTUP_READY_FILE")))
        {
            // Native acceptance needs useful diagnostics when initialization never reaches Opened.
            System.Diagnostics.Trace.Listeners.Add(new System.Diagnostics.TextWriterTraceListener(Console.Error));
            System.Diagnostics.Trace.AutoFlush = true;
            System.Diagnostics.Trace.WriteLine("Startup check: entering installer hooks.");
        }
        // First, before any UI. The installer re-runs the executable with hook arguments during
        // install, update and uninstall, and this is what handles them and exits. Starting
        // Avalonia first would flash a window during a silent install and leave shortcuts
        // unwritten.
        VelopackApp.Build().Run();

        System.Diagnostics.Trace.WriteLine("Startup check: initializing the desktop framework.");
        BuildAvaloniaApp().StartWithClassicDesktopLifetime(args);
    }

    // Referenced by name by the Avalonia XAML previewer, so the signature is fixed.
    public static AppBuilder BuildAvaloniaApp()
        => AppBuilder.Configure<App>()
            .UsePlatformDetect()
            .WithInterFont()
            .LogToTrace();
}
