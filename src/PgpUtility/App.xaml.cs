using System.Windows;
using PgpUtility.Services;
using PgpUtility.ViewModels;

namespace PgpUtility;

public partial class App : Application
{
    protected override void OnStartup(StartupEventArgs e)
    {
        base.OnStartup(e);

        var pgpService = new PgpService();
        var keyStoreService = new KeyStoreService(pgpService);
        var fileDialogService = new FileDialogService();
        var mainViewModel = new MainViewModel(pgpService, keyStoreService, fileDialogService);

        var mainWindow = new MainWindow { DataContext = mainViewModel };
        mainWindow.Show();
    }
}
