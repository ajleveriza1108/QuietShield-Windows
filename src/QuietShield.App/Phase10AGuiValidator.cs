using System.Windows;
using System.Windows.Automation;
using System.Windows.Controls;
using System.Windows.Media;
using System.Windows.Threading;
using QuietShield.App.ViewModels;

namespace QuietShield.App;

public sealed record Phase10AGuiValidationResult(
    int SchemaVersion,
    string Status,
    Phase9GuiValidationResult Phase9Baseline,
    bool ServiceStatusDisplayed,
    bool DiagnosticCommunicationDisplayed,
    bool PersistentEnforcementInactive,
    bool MisleadingControlsAbsent,
    bool Responsive,
    IReadOnlyList<string> Errors);

public static class Phase10AGuiValidator
{
    public static async Task<Phase10AGuiValidationResult> ValidateAsync(MainWindow window, MainViewModel viewModel, string planExportPath)
    {
        var baseline = await Phase9GuiValidator.ValidateAsync(window, viewModel, planExportPath).ConfigureAwait(true);
        var errors = new List<string>();
        viewModel.SelectedPage = viewModel.NavigationItems[0];
        window.ApplyValidationSize(1024d, 640d);
        window.ResponsivePage.ScrollViewer.ScrollToEnd();
        await window.Dispatcher.InvokeAsync(static () => { }, DispatcherPriority.Render);
        window.UpdateLayout();

        var text = string.Join(" ", FindVisualChildren<TextBlock>(window).Select(static item => item.Text));
        var status = viewModel.ServiceInstallationStatus == "Not installed" && text.Contains("Persistent service foundation", StringComparison.Ordinal);
        if (!status) errors.Add("The service installation status is not explicit.");
        var communication = viewModel.ServiceCommunicationStatus == "Diagnostic mode";
        if (!communication) errors.Add("The local diagnostic communication status was not received.");
        var inactive = viewModel.PersistentEnforcementStatus == "Not active" && text.Contains("PERSISTENT ENFORCEMENT", StringComparison.Ordinal);
        if (!inactive) errors.Add("Persistent enforcement is not explicitly inactive.");
        var prohibited = FindVisualChildren<Button>(window).Select(static button => AutomationProperties.GetName(button).Length > 0
                ? AutomationProperties.GetName(button) : button.Content?.ToString() ?? string.Empty)
            .Any(static name => name.Contains("Install Service", StringComparison.OrdinalIgnoreCase) || name.Equals("Start Service", StringComparison.OrdinalIgnoreCase) ||
                                name.Equals("Apply", StringComparison.OrdinalIgnoreCase) || name.Equals("Enforce", StringComparison.OrdinalIgnoreCase));
        if (prohibited) errors.Add("A prohibited service installation or enforcement action is visible.");
        var responsive = window.ResponsivePage.ScrollViewer.ScrollableWidth <= 1d;
        if (!responsive) errors.Add("The service status panel introduced horizontal overflow.");
        return new(1, baseline.Status == "Passed" && errors.Count == 0 ? "Passed" : "Failed", baseline, status, communication, inactive, !prohibited, responsive, errors);
    }

    private static IEnumerable<T> FindVisualChildren<T>(DependencyObject root) where T : DependencyObject
    {
        for (var index = 0; index < VisualTreeHelper.GetChildrenCount(root); index++)
        {
            var child = VisualTreeHelper.GetChild(root, index);
            if (child is T typed) yield return typed;
            foreach (var descendant in FindVisualChildren<T>(child)) yield return descendant;
        }
    }
}
