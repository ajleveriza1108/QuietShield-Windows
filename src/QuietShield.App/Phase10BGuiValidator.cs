using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
using System.Windows.Threading;
using QuietShield.App.ViewModels;

namespace QuietShield.App;

public sealed record Phase10BGuiValidationResult(int SchemaVersion, string Status, Phase10AGuiValidationResult Phase10ABaseline,
    bool LifecycleStatusVisible, bool EnforcementStatusVisible, bool CustomerActivationControlsAbsent, bool Responsive, IReadOnlyList<string> Errors);

public static class Phase10BGuiValidator
{
    public static async Task<Phase10BGuiValidationResult> ValidateAsync(MainWindow window, MainViewModel viewModel, string planExportPath)
    {
        var baseline = await Phase10AGuiValidator.ValidateAsync(window, viewModel, planExportPath).ConfigureAwait(true);
        var errors = new List<string>();
        viewModel.SelectedPage = viewModel.NavigationItems[0];
        window.ApplyValidationSize(1024d, 640d);
        window.ResponsivePage.ScrollViewer.ScrollToEnd();
        await window.Dispatcher.InvokeAsync(static () => { }, DispatcherPriority.Render);
        window.UpdateLayout();
        var text = string.Join(" ", FindVisualChildren<TextBlock>(window).Select(static item => item.Text));
        var lifecycle = text.Contains("SERVICE INSTALLED", StringComparison.Ordinal) && text.Contains("SERVICE RUNNING", StringComparison.Ordinal) && text.Contains("IPC CONNECTED", StringComparison.Ordinal);
        if (!lifecycle) errors.Add("The exact service lifecycle status fields are missing.");
        var enforcement = text.Contains("PERSISTENT ENFORCEMENT AVAILABLE", StringComparison.Ordinal) && text.Contains("TRANSACTION STATUS", StringComparison.Ordinal) && text.Contains("LAST-KNOWN-GOOD POLICY", StringComparison.Ordinal);
        if (!enforcement) errors.Add("The persistent enforcement status fields are missing.");
        var prohibited = FindVisualChildren<Button>(window).Any(static button => (button.Content?.ToString() ?? string.Empty) is "Install Service" or "Start Service" or "Apply" or "Enforce");
        if (prohibited) errors.Add("A customer-facing service or enforcement action is visible.");
        var responsive = window.ResponsivePage.ScrollViewer.ScrollableWidth <= 1d;
        if (!responsive) errors.Add("The Phase 10B service status introduced horizontal overflow.");
        return new(1, baseline.Status == "Passed" && errors.Count == 0 ? "Passed" : "Failed", baseline, lifecycle, enforcement, !prohibited, responsive, errors);
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
