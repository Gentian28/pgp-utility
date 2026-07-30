using System.Windows.Controls;
using PgpUtility.ViewModels;

namespace PgpUtility.Views;

public partial class KeyGenerationView : UserControl
{
    public KeyGenerationView()
    {
        InitializeComponent();
    }

    private void PassphraseBox_PasswordChanged(object sender, System.Windows.RoutedEventArgs e)
    {
        if (sender is PasswordBox pb && DataContext is KeyGenerationViewModel vm)
            vm.Passphrase = pb.Password;
    }

    private void ConfirmPassphraseBox_PasswordChanged(object sender, System.Windows.RoutedEventArgs e)
    {
        if (sender is PasswordBox pb && DataContext is KeyGenerationViewModel vm)
            vm.ConfirmPassphrase = pb.Password;
    }
}
