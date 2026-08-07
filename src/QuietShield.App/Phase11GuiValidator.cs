using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
using System.Windows.Threading;
using QuietShield.App.ViewModels;

namespace QuietShield.App;

public sealed record Phase11GuiValidationResult(
    int SchemaVersion,
    string Status,
    Phase10BGuiValidationResult Phase10BBaseline,
    bool RefreshServiceStatusVisible,
    bool ServiceStatusRefreshSucceeded,
    bool ProgramLockIntegrationStatusVisible,
    bool CustomerEnforcementControlsAbsent,
    bool Responsive,
    IReadOnlyList<string> Errors);

public static class Phase11GuiValidator
{
    public static async Task<Phase11GuiValidationResult> ValidateAsync(
        MainWindow window,
        MainViewModel viewModel,
        string planExportPath)
    {
        var baseline = await Phase10BGuiValidator.ValidateAsync(
            window,
            viewModel,
            planExportPath).ConfigureAwait(true);

        var errors = new List<string>();

        viewModel.SelectedPage = viewModel.NavigationItems[0];
        window.ApplyValidationSize(1024d, 640d);
        await viewModel.RefreshPersistentServiceStatusAsync(CancellationToken.None).ConfigureAwait(true);
        await window.Dispatcher.InvokeAsync(static () => { }, DispatcherPriority.Render);
        window.UpdateLayout();

        var dashboardButtons = FindVisualChildren<Button>(window).ToArray();
        var refreshVisible = dashboardButtons.Any(static button =>
            (button.Content?.ToString() ?? string.Empty).Contains(
                "Refresh Service Status",
                StringComparison.OrdinalIgnoreCase));

        if (!refreshVisible)
            errors.Add("Refresh Service Status is not visible on the dashboard.");

        var refreshSucceeded =
            viewModel.ServiceIpcConnected.Equals("Yes", StringComparison.Ordinal) &&
            !viewModel.ServiceCommunicationStatus.Contains("unavailable", StringComparison.OrdinalIgnoreCase);

        if (!refreshSucceeded)
            errors.Add("The Phase 11 desktop could not refresh status from the diagnostic service IPC endpoint.");

        viewModel.SelectedPage = viewModel.NavigationItems.First(static item =>
            item.Title.Equals("Program Connection Lock", StringComparison.Ordinal));

        await window.Dispatcher.InvokeAsync(static () => { }, DispatcherPriority.Render);
        window.UpdateLayout();

        var programLockText = string.Join(
            " ",
            FindVisualChildren<TextBlock>(window).Select(static item => item.Text));

        var integrationStatusVisible =
            programLockText.Contains("Phase 11", StringComparison.Ordinal) &&
            programLockText.Contains("validated service", StringComparison.OrdinalIgnoreCase);

        if (!integrationStatusVisible)
            errors.Add("Program Connection Lock does not show the Phase 11 validated-service integration status.");

        var prohibited = FindVisualChildren<Button>(window).Any(static button =>
        {
            var content = (button.Content?.ToString() ?? string.Empty).Replace("_", string.Empty, StringComparison.Ordinal);
            return content.Equals("Install Service", StringComparison.OrdinalIgnoreCase) ||
                   content.Equals("Start Service", StringComparison.OrdinalIgnoreCase) ||
                   content.Equals("Apply", StringComparison.OrdinalIgnoreCase) ||
                   content.Equals("Enforce", StringComparison.OrdinalIgnoreCase) ||
                   content.Equals("Block Now", StringComparison.OrdinalIgnoreCase);
        });

        if (prohibited)
            errors.Add("A customer-facing persistent enforcement action is visible before Phase 11 activation approval.");

        var responsive = window.ResponsivePage.ScrollViewer.ScrollableWidth <= 1d;
        if (!responsive)
            errors.Add("Phase 11 integration introduced horizontal overflow.");

        var passed =
            baseline.Status == "Passed" &&
            errors.Count == 0;

        return new(
            1,
            passed ? "Passed" : "Failed",
            baseline,
            refreshVisible,
            refreshSucceeded,
            integrationStatusVisible,
            !prohibited,
            responsive,
            errors);
    }

    private static IEnumerable<T> FindVisualChildren<T>(DependencyObject root)
        where T : DependencyObject
    {
        for (var index = 0; index < VisualTreeHelper.GetChildrenCount(root); index++)
        {
            var child = VisualTreeHelper.GetChild(root, index);
            if (child is T typed)
                yield return typed;

            foreach (var descendant in FindVisualChildren<T>(child))
                yield return descendant;
        }
    }
}
