using System.Collections.Specialized;
using System.Windows;
using System.Windows.Controls;
using PgpUtility.ViewModels;

namespace PgpUtility.Views;

public partial class EncryptDecryptView : UserControl
{
    public EncryptDecryptView()
    {
        InitializeComponent();
        DataContextChanged += OnDataContextChanged;
    }

    private void OnDataContextChanged(object sender, DependencyPropertyChangedEventArgs e)
    {
        if (e.OldValue is EncryptDecryptViewModel oldVm)
            oldVm.Files.CollectionChanged -= OnFilesChanged;
        if (e.NewValue is EncryptDecryptViewModel newVm)
        {
            newVm.Files.CollectionChanged += OnFilesChanged;
            UpdateDropHint(newVm.Files.Count);
        }
    }

    private void OnFilesChanged(object? sender, NotifyCollectionChangedEventArgs e)
    {
        if (DataContext is EncryptDecryptViewModel vm)
            UpdateDropHint(vm.Files.Count);
    }

    private void UpdateDropHint(int count)
    {
        DropHintText.Visibility = count == 0 ? Visibility.Visible : Visibility.Collapsed;
    }

    private void OnDragOver(object sender, DragEventArgs e)
    {
        if (e.Data.GetDataPresent(DataFormats.FileDrop))
        {
            e.Effects = DragDropEffects.Copy;
            e.Handled = true;
        }
    }

    private void OnDrop(object sender, DragEventArgs e)
    {
        if (e.Data.GetDataPresent(DataFormats.FileDrop) &&
            e.Data.GetData(DataFormats.FileDrop) is string[] files &&
            DataContext is EncryptDecryptViewModel vm)
        {
            vm.AddFilePaths(files);
        }
    }

    private void PassphraseBox_PasswordChanged(object sender, RoutedEventArgs e)
    {
        if (sender is PasswordBox pb && DataContext is EncryptDecryptViewModel vm)
            vm.Passphrase = pb.Password;
    }
}
