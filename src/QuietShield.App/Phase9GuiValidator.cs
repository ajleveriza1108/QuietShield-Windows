using System.Diagnostics;
using System.Windows;
using System.Windows.Automation;
using System.Windows.Controls;
using System.Windows.Media;
using System.Windows.Threading;
using QuietShield.App.ViewModels;

namespace QuietShield.App;

public sealed record Phase9GuiValidationResult(
    int SchemaVersion,
    string Status,
    Phase8GuiValidationResult Phase8Baseline,
    bool RehearsalStatusSectionPassed,
    bool DedicatedTestBannerPassed,
    bool PermanentEnforcementInactive,
    bool MisleadingPermanentControlsAbsent,
    bool Responsive,
    IReadOnlyList<string> Errors);

public static class Phase9GuiValidator
{
    public static async Task<Phase9GuiValidationResult> ValidateAsync(
        MainWindow window,
        MainViewModel viewModel,
        string planExportPath)
    {
        var baseline = await Phase8GuiValidator.ValidateAsync(window, viewModel, planExportPath).ConfigureAwait(true);
        var errors = new List<string>();
        var stopwatch = Stopwatch.StartNew();
        viewModel.SelectedPage = viewModel.NavigationItems.Single(static page => page.Title == "Program Connection Lock");
        window.ApplyValidationSize(1024d, 640d);
        window.ResponsivePage.ScrollViewer.ScrollToTop();
        await window.Dispatcher.InvokeAsync(static () => { }, DispatcherPriority.Render);
        window.UpdateLayout();

        var readiness = !string.IsNullOrWhiteSpace(viewModel.FirewallRehearsalCapability) &&
                        viewModel.RehearsalTestExecutableReadiness.Contains("Dedicated .NET 10 probe", StringComparison.Ordinal) &&
                        viewModel.RehearsalEndpointReadiness.Contains("preflight", StringComparison.OrdinalIgnoreCase) &&
                        viewModel.RehearsalBackupReadiness.Contains("SHA-256", StringComparison.Ordinal) &&
                        viewModel.RehearsalWatchdogReadiness.Contains("heartbeat", StringComparison.OrdinalIgnoreCase) &&
                        viewModel.LastFirewallRehearsalResult.Contains("Not run", StringComparison.Ordinal) &&
                        viewModel.LastFirewallRollbackResult.Contains("no rehearsal rule", StringComparison.OrdinalIgnoreCase);
        if (!readiness) errors.Add("The Phase 9 rehearsal status section is incomplete.");

        var pageText = string.Join(" ", FindVisualChildren<TextBlock>(window).Select(static item => item.Text));
        var banner = pageText.Contains("Temporary dedicated test only. No installed application will be blocked.", StringComparison.Ordinal);
        if (!banner) errors.Add("The dedicated-test-only banner is missing.");
        var inactive = viewModel.PermanentFirewallEnforcementStatus.Equals("Not active", StringComparison.Ordinal) &&
                       pageText.Contains("Permanent enforcement", StringComparison.Ordinal);
        if (!inactive) errors.Add("Permanent enforcement is not clearly inactive.");

        var prohibited = FindVisualChildren<Button>(window)
            .Select(static button => AutomationProperties.GetName(button).Length > 0 ? AutomationProperties.GetName(button) : button.Content?.ToString() ?? string.Empty)
            .Where(static name => name.Equals("Apply", StringComparison.OrdinalIgnoreCase) || name.Equals("Enforce", StringComparison.OrdinalIgnoreCase))
            .ToArray();
        var controlsAbsent = prohibited.Length == 0;
        if (!controlsAbsent) errors.Add("A permanent Apply or Enforce control is visible.");

        window.ResponsivePage.ScrollViewer.ScrollToEnd();
        await window.Dispatcher.InvokeAsync(static () => { }, DispatcherPriority.Background);
        stopwatch.Stop();
        var responsive = window.ResponsivePage.ScrollViewer.ScrollableWidth <= 1d && stopwatch.Elapsed < TimeSpan.FromSeconds(15);
        if (!responsive) errors.Add("The Phase 9 status section introduced horizontal overflow or exceeded the responsiveness budget.");
        viewModel.SelectedPage = viewModel.NavigationItems[0];
        return new(1, baseline.Status == "Passed" && errors.Count == 0 ? "Passed" : "Failed", baseline, readiness, banner, inactive, controlsAbsent, responsive, errors);
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
