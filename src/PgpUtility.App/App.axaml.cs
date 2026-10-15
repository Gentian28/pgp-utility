using Avalonia;
using Avalonia.Controls;
using Avalonia.Controls.ApplicationLifetimes;
using Avalonia.Data.Core.Plugins;
using Avalonia.Markup.Xaml;
using PgpUtility.App.Services;
using PgpUtility.App.ViewModels;
using PgpUtility.Services;

namespace PgpUtility.App;

public partial class App : Application
{
    public override void Initialize() => AvaloniaXamlLoader.Load(this);

    public override void OnFrameworkInitializationCompleted()
    {
        if (ApplicationLifetime is IClassicDesktopStyleApplicationLifetime desktop)
        {
            // CommunityToolkit's generated properties already raise change notifications, so
            // Avalonia's reflection-based validation would report the same errors twice.
            DisableDuplicateValidation();

            System.Diagnostics.Trace.WriteLine("Startup check: creating the main window.");
            var window = new MainWindow();

            // The pickers and the clipboard both hang off the window, which does not exist when
            // the view models would otherwise be built. Resolving lazily through a delegate keeps
            // the view models free of any window reference.
            TopLevel? TopLevel() => window;

            var pgpService = new PgpService();
            var keyStore = new KeyStoreService(pgpService);
            System.Diagnostics.Trace.WriteLine("Startup check: key store initialized.");

            window.DataContext = new MainViewModel(
                pgpService,
                new PgpSignatureService(),
                keyStore,
                new StorageFilePickerService(TopLevel),
                new ClipboardService(TopLevel),
                new ThemeService());

            // A live process can be deadlocked before showing a window. Native release checks
            // require an explicit signal from Opened, after store and view-model initialization.
            string? readyFile = Environment.GetEnvironmentVariable("PGPUTILITY_STARTUP_READY_FILE");
            if (!string.IsNullOrWhiteSpace(readyFile))
            {
                window.Opened += async (_, _) =>
                {
                    System.Diagnostics.Trace.WriteLine("Startup check: main window opened.");
                    try { await FileTransaction.WriteTextAsync(readyFile, "ready"); }
                    catch (Exception exception) { System.Diagnostics.Trace.TraceError("Startup readiness signal failed: {0}", exception.Message); }
                };
            }

            desktop.MainWindow = window;
            System.Diagnostics.Trace.WriteLine("Startup check: main window assigned.");
        }

        base.OnFrameworkInitializationCompleted();
    }

    private static void DisableDuplicateValidation()
    {
        var toRemove = BindingPlugins.DataValidators
            .OfType<DataAnnotationsValidationPlugin>()
            .ToArray();

        foreach (var plugin in toRemove)
            BindingPlugins.DataValidators.Remove(plugin);
    }
}
