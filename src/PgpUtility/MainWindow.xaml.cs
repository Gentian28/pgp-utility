using System.Windows;
using PgpUtility.ViewModels;

namespace PgpUtility;

public partial class MainWindow : Window
{
    public MainWindow()
    {
        InitializeComponent();
    }

    private void ToggleLogPanel_Click(object sender, RoutedEventArgs e)
    {
        if (DataContext is MainViewModel vm)
            vm.IsLogPanelVisible = !vm.IsLogPanelVisible;
    }
}
