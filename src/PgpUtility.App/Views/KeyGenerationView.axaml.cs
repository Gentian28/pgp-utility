using Avalonia.Controls;
using Avalonia.Interactivity;
using PgpUtility.App.ViewModels;

namespace PgpUtility.App.Views;

public partial class KeyGenerationView : UserControl
{
    private KeyGenerationViewModel? _subscribed;

    public KeyGenerationView()
    {
        InitializeComponent();
        PassphraseBox.TextChanged += OnPassphraseChanged;
        ConfirmPassphraseBox.TextChanged += OnConfirmPassphraseChanged;
        DataContextChanged += OnDataContextChanged;
    }

    private void OnDataContextChanged(object? sender, EventArgs e)
    {
        if (_subscribed is not null)
            _subscribed.PassphraseCleared -= OnPassphraseCleared;

        _subscribed = DataContext as KeyGenerationViewModel;

        if (_subscribed is not null)
            _subscribed.PassphraseCleared += OnPassphraseCleared;
    }

    // Avalonia has no PasswordBox and no SecureString equivalent, so TextBox.Text is a managed
    // string this code cannot zero. The array is zeroed all the way through the service; clearing
    // the box once the key is written is the only lever available for the string itself.
    private void OnPassphraseChanged(object? sender, TextChangedEventArgs e)
    {
        if (DataContext is KeyGenerationViewModel vm)
            vm.Passphrase = PassphraseBox.Text?.ToCharArray() ?? [];
    }

    private void OnConfirmPassphraseChanged(object? sender, TextChangedEventArgs e)
    {
        if (DataContext is KeyGenerationViewModel vm)
            vm.ConfirmPassphrase = ConfirmPassphraseBox.Text?.ToCharArray() ?? [];
    }

    private void OnPassphraseCleared(object? sender, EventArgs e)
    {
        PassphraseBox.Clear();
        ConfirmPassphraseBox.Clear();
    }
}
