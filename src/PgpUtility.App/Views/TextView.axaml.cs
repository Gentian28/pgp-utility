using Avalonia.Controls;
using Avalonia.Interactivity;
using PgpUtility.App.ViewModels;

namespace PgpUtility.App.Views;

public partial class TextView : UserControl
{
    private TextViewModel? _subscribed;

    public TextView()
    {
        InitializeComponent();
        PassphraseBox.TextChanged += OnPassphraseChanged;
        DataContextChanged += OnDataContextChanged;
    }

    private void OnDataContextChanged(object? sender, EventArgs e)
    {
        if (_subscribed is not null)
            _subscribed.PassphraseCleared -= OnPassphraseCleared;

        _subscribed = DataContext as TextViewModel;

        if (_subscribed is not null)
            _subscribed.PassphraseCleared += OnPassphraseCleared;
    }

    private void OnPassphraseChanged(object? sender, TextChangedEventArgs e)
    {
        if (DataContext is TextViewModel vm)
            vm.Passphrase = PassphraseBox.Text?.ToCharArray() ?? [];
    }

    private void OnPassphraseCleared(object? sender, EventArgs e) => PassphraseBox.Clear();
}
