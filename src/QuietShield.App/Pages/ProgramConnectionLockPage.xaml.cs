using System.Windows;
using System.Windows.Controls;
using QuietShield.App.ViewModels;

namespace QuietShield.App.Pages;

public partial class ProgramConnectionLockPage : UserControl
{
    public ProgramConnectionLockPage()
    {
        InitializeComponent();
    }

    private void ApplyAppRuleButton_Click(
        object sender,
        RoutedEventArgs args)
    {
        if (DataContext is not MainViewModel viewModel)
        {
            return;
        }

        var command = viewModel.SavePersistentProgramPolicyCommand;

        if (!command.CanExecute(null))
        {
            MessageBox.Show(
                "QuietShield cannot apply this app rule yet. Check the selected application, Protection Service status, and Service IPC connection.",
                "App Rule Not Ready",
                MessageBoxButton.OK,
                MessageBoxImage.Information);

            return;
        }

        if (string.Equals(
            viewModel.SelectedPolicy.ToString(),
            "Blocked",
            StringComparison.Ordinal))
        {
            var appName =
                string.IsNullOrWhiteSpace(viewModel.PersistentWorkflowApplication)
                    ? "the selected application"
                    : viewModel.PersistentWorkflowApplication;

            var result = MessageBox.Show(
                "Block internet access for \"" +
                appName +
                "\"?\n\n" +
                "This is a persistent app rule. Blocking internet access can prevent sign-in, synchronization, updates, downloads, licensing, cloud features, and normal online operation.\n\n" +
                "QuietShield will still validate the application and refuse protected Windows system components.\n\n" +
                "Continue?",
                "Confirm Internet Block",
                MessageBoxButton.YesNo,
                MessageBoxImage.Warning,
                MessageBoxResult.No);

            if (result != MessageBoxResult.Yes)
            {
                return;
            }
        }

        command.Execute(null);
    }
}
