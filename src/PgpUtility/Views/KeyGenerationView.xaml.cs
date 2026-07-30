using System.Windows;
using System.Windows.Controls;
using PgpUtility.ViewModels;

namespace PgpUtility.Views;

public partial class KeyGenerationView : UserControl
{
    public KeyGenerationView()
    {
        InitializeComponent();
        DataContextChanged += OnDataContextChanged;
    }

    private void OnDataContextChanged(object sender, DependencyPropertyChangedEventArgs e)
    {
        if (e.OldValue is KeyGenerationViewModel oldVm)
            oldVm.PassphraseCleared -= OnPassphraseCleared;
        if (e.NewValue is KeyGenerationViewModel newVm)
            newVm.PassphraseCleared += OnPassphraseCleared;
    }

    // The view model zeroes its arrays after a successful generation. Empty the boxes to match,
    // otherwise they keep showing dots for a passphrase nothing holds any more.
    private void OnPassphraseCleared(object? sender, EventArgs e)
    {
        PassphraseBox.Clear();
        ConfirmPassphraseBox.Clear();
    }

    private void PassphraseBox_PasswordChanged(object sender, RoutedEventArgs e)
    {
        if (sender is PasswordBox pb && DataContext is KeyGenerationViewModel vm)
            vm.Passphrase = pb.ReadPassphrase();
    }

    private void ConfirmPassphraseBox_PasswordChanged(object sender, RoutedEventArgs e)
    {
        if (sender is PasswordBox pb && DataContext is KeyGenerationViewModel vm)
            vm.ConfirmPassphrase = pb.ReadPassphrase();
    }
}
