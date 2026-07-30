using Avalonia.Controls;
using Avalonia.Input;
using Avalonia.Interactivity;
using PgpUtility.App.ViewModels;

namespace PgpUtility.App.Views;

public partial class SignVerifyView : UserControl
{
    private SignVerifyViewModel? _subscribed;

    public SignVerifyView()
    {
        InitializeComponent();
        PassphraseBox.TextChanged += OnPassphraseChanged;
        DataContextChanged += OnDataContextChanged;

        AddHandler(DragDrop.DragOverEvent, OnDragOver);
        AddHandler(DragDrop.DropEvent, OnDrop);
        DragDrop.SetAllowDrop(this, true);
    }

    private void OnDataContextChanged(object? sender, EventArgs e)
    {
        if (_subscribed is not null)
            _subscribed.PassphraseCleared -= OnPassphraseCleared;

        _subscribed = DataContext as SignVerifyViewModel;

        if (_subscribed is not null)
            _subscribed.PassphraseCleared += OnPassphraseCleared;
    }

    private void OnPassphraseChanged(object? sender, TextChangedEventArgs e)
    {
        if (DataContext is SignVerifyViewModel vm)
            vm.Passphrase = PassphraseBox.Text?.ToCharArray() ?? [];
    }

    private void OnPassphraseCleared(object? sender, EventArgs e) => PassphraseBox.Clear();

    private static void OnDragOver(object? sender, DragEventArgs e)
    {
        e.DragEffects = DroppedFiles.HasFiles(e) ? DragDropEffects.Copy : DragDropEffects.None;
        e.Handled = true;
    }

    private void OnDrop(object? sender, DragEventArgs e)
    {
        if (DataContext is not SignVerifyViewModel vm) return;

        var paths = DroppedFiles.PathsFrom(e);
        if (paths.Count > 0)
        {
            vm.AcceptDroppedFiles(paths);
            e.Handled = true;
        }
    }
}
