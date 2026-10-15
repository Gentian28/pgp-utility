using Avalonia.Controls;
using PgpUtility.ViewModels;

namespace PgpUtility.App.Views;

public partial class KeyManagementView : UserControl
{
    private KeyManagementViewModel? _subscribed;

    public KeyManagementView()
    {
        InitializeComponent();
        SizeChanged += (_, _) => UpdateLayoutForWidth();
        DataContextChanged += (_, _) =>
        {
            if (_subscribed is not null) _subscribed.PassphraseCleared -= ClearPassphrases;
            _subscribed = DataContext as KeyManagementViewModel;
            if (_subscribed is not null) _subscribed.PassphraseCleared += ClearPassphrases;
        };
        CurrentPassphraseBox.TextChanged += (_, _) => { if (_subscribed is not null) _subscribed.CurrentPassphrase = CurrentPassphraseBox.Text?.ToCharArray() ?? []; };
        NewPassphraseBox.TextChanged += (_, _) => { if (_subscribed is not null) _subscribed.NewPassphrase = NewPassphraseBox.Text?.ToCharArray() ?? []; };
        ConfirmNewPassphraseBox.TextChanged += (_, _) => { if (_subscribed is not null) _subscribed.ConfirmNewPassphrase = ConfirmNewPassphraseBox.Text?.ToCharArray() ?? []; };
    }

    private void UpdateLayoutForWidth()
    {
        bool narrow = Bounds.Width < 760;
        KeyPanes.ColumnDefinitions = new ColumnDefinitions(narrow ? "*" : "*,360");
        Grid.SetColumn(KeyDetailPane, narrow ? 0 : 1);
        Grid.SetRow(KeyDetailPane, narrow ? 1 : 0);
    }

    private void ClearPassphrases(object? sender, EventArgs e)
    {
        CurrentPassphraseBox.Clear();
        NewPassphraseBox.Clear();
        ConfirmNewPassphraseBox.Clear();
    }
}
