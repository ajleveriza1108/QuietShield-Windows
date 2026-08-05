using System.Windows;
using QuietShield.App.ViewModels;

namespace QuietShield.App;

public partial class MainWindow : Window
{
    public MainWindow(MainViewModel viewModel)
    {
        InitializeComponent();
        DataContext = viewModel;
    }
}
