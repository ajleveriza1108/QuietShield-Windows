using System.Windows;
using System.Windows.Controls;
using QuietShield.App.ViewModels;

namespace QuietShield.App.Pages;

public partial class DataSavingPage : UserControl
{
    public DataSavingPage()
    {
        InitializeComponent();
    }

    private void AllowInternetCheckBox_Unchecked(
        object sender,
        RoutedEventArgs args)
    {
        if (sender is not CheckBox checkBox ||
            checkBox.DataContext is not DataSavingApplicationItem application)
        {
            return;
        }

        if (application.IsSystemComponent)
        {
            application.IsAllowed = true;

            MessageBox.Show(
                "This is a protected Windows system component. QuietShield will not restrict its internet access through Data Saving.",
                "Protected Windows Component",
                MessageBoxButton.OK,
                MessageBoxImage.Information);

            return;
        }

        var result = MessageBox.Show(
            "Block internet access for \"" +
            application.DisplayName +
            "\" in the Data Saving plan?\n\n" +
            "When machine-wide Data Saving enforcement is enabled, this can interrupt sign-in, synchronization, updates, downloads, licensing, cloud features, and other online functions for this app.\n\n" +
            "Continue?",
            "Confirm Internet Restriction",
            MessageBoxButton.YesNo,
            MessageBoxImage.Warning,
            MessageBoxResult.No);

        if (result != MessageBoxResult.Yes)
        {
            application.IsAllowed = true;
        }
    }
}
