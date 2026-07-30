using Avalonia.Controls;
using Avalonia.Interactivity;
using PgpUtility.App.ViewModels;

namespace PgpUtility.App.Views;

public partial class EncryptDecryptView : UserControl
{
    public EncryptDecryptView()
    {
        InitializeComponent();
        PassphraseBox.TextChanged += OnPassphraseChanged;
        DataContextChanged += OnDataContextChanged;
    }

    private EncryptDecryptViewModel? _subscribed;

    private void OnDataContextChanged(object? sender, EventArgs e)
    {
        if (_subscribed is not null)
            _subscribed.PassphraseCleared -= OnPassphraseCleared;

        _subscribed = DataContext as EncryptDecryptViewModel;

        if (_subscribed is not null)
            _subscribed.PassphraseCleared += OnPassphraseCleared;
    }

    /// <summary>
    /// Pushes the typed passphrase to the view model as a char array.
    /// </summary>
    /// <remarks>
    /// Avalonia has no PasswordBox and no SecureString equivalent, so TextBox.Text is a managed
    /// string this code does not own and cannot zero. The array below can be zeroed and is, all
    /// the way through the service; the string inside the TextBox is the part that cannot be, and
    /// clearing the box on completion is the only lever available. A real reduction from the WPF
    /// build's SecurePassword path, and worth being honest about rather than papering over.
    /// </remarks>
    private void OnPassphraseChanged(object? sender, TextChangedEventArgs e)
    {
        if (DataContext is EncryptDecryptViewModel vm)
            vm.Passphrase = PassphraseBox.Text?.ToCharArray() ?? [];
    }

    private void OnPassphraseCleared(object? sender, EventArgs e) => PassphraseBox.Clear();
}
