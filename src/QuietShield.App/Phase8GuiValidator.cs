using System.Diagnostics;
using System.IO;
using System.Text.Json;
using System.Windows;
using System.Windows.Automation;
using System.Windows.Controls;
using System.Windows.Media;
using System.Windows.Threading;
using QuietShield.App.ViewModels;

namespace QuietShield.App;

public sealed record Phase8GuiValidationResult(
    int SchemaVersion,
    string Status,
    Phase7GuiValidationResult Phase7Baseline,
    bool TransactionPlanSmokePassed,
    bool PlanExportSmokePassed,
    bool BackupRollbackReadinessPassed,
    bool PlanViewerVirtualized,
    bool MisleadingEnforcementControlsAbsent,
    bool InactiveBannerPassed,
    bool LongTextAffordancesPassed,
    bool UpdatedPageResponsive,
    IReadOnlyList<string> Errors);

public static class Phase8GuiValidator
{
    private static readonly string[] ProhibitedButtonNames = { "Apply", "Activate", "Enforce", "Administrator" };

    public static async Task<Phase8GuiValidationResult> ValidateAsync(
        MainWindow window,
        MainViewModel viewModel,
        string planExportPath)
    {
        ArgumentNullException.ThrowIfNull(window);
        ArgumentNullException.ThrowIfNull(viewModel);
        ArgumentException.ThrowIfNullOrWhiteSpace(planExportPath);
        var baseline = await Phase7GuiValidator.ValidateAsync(window, viewModel).ConfigureAwait(true);
        var errors = new List<string>();
        var stopwatch = Stopwatch.StartNew();

        viewModel.SelectedPage = viewModel.NavigationItems.Single(static page => page.Title == "Program Connection Lock");
        window.ApplyValidationSize(1024d, 640d);
        window.ResponsivePage.ScrollViewer.ScrollToTop();
        await window.Dispatcher.InvokeAsync(static () => { }, DispatcherPriority.Render);
        window.UpdateLayout();

        var planSmoke = viewModel.ProgramLockPlanOperations.Count > 0 &&
                        viewModel.ProposedRuleOperationCount == viewModel.ProgramLockPlanOperations.Count &&
                        viewModel.TransactionPreviewStatus.Contains("executable: False", StringComparison.Ordinal);
        if (!planSmoke) errors.Add("The deterministic non-executable transaction plan preview did not produce operations.");

        var exportPassed = false;
        if (planSmoke)
        {
            await viewModel.ExportEnforcementPlanForValidationAsync(planExportPath, CancellationToken.None).ConfigureAwait(true);
            using var document = JsonDocument.Parse(await File.ReadAllTextAsync(planExportPath).ConfigureAwait(true));
            exportPassed = document.RootElement.GetProperty("canExecute").ValueKind == JsonValueKind.False &&
                           document.RootElement.GetProperty("operations").GetArrayLength() == viewModel.ProposedRuleOperationCount;
        }
        if (!exportPassed) errors.Add("The exported plan was absent, executable, malformed, or did not match the preview.");

        var readiness = viewModel.BackupReadiness.Contains("SHA-256", StringComparison.Ordinal) &&
                        viewModel.RollbackReadiness.Contains("interrupted", StringComparison.OrdinalIgnoreCase) &&
                        viewModel.EmergencyRecoveryReadiness.Contains("QuietShield-owned", StringComparison.Ordinal);
        if (!readiness) errors.Add("Backup, rollback, or emergency recovery readiness is incomplete.");

        var planList = FindVisualChildren<ListView>(window).SingleOrDefault(static list => list.Name == "ProgramLockTransactionPlanList");
        var virtualized = planList is not null && VirtualizingPanel.GetIsVirtualizing(planList) &&
                          VirtualizingPanel.GetVirtualizationMode(planList) == VirtualizationMode.Recycling;
        if (!virtualized) errors.Add("The transaction-plan viewer is not recycling-virtualized.");

        var prohibited = FindVisualChildren<Button>(window)
            .Select(static button => AutomationProperties.GetName(button).Length > 0
                ? AutomationProperties.GetName(button)
                : button.Content?.ToString() ?? string.Empty)
            .Where(name => ProhibitedButtonNames.Any(prohibitedName => name.Equals(prohibitedName, StringComparison.OrdinalIgnoreCase)))
            .ToArray();
        var noMisleadingControls = prohibited.Length == 0;
        if (!noMisleadingControls) errors.Add("A prohibited modifying or elevation button is visible: " + string.Join(", ", prohibited));

        var pageText = string.Join(" ", FindVisualChildren<TextBlock>(window).Select(static block => block.Text));
        var banner = pageText.Contains("Enforcement is not active. No Windows Firewall or WFP rule has been changed.", StringComparison.Ordinal);
        if (!banner) errors.Add("The required Phase 8 inactive-enforcement banner is not visible.");

        var longText = viewModel.ProgramLockPlanOperations.All(static operation =>
            !string.IsNullOrWhiteSpace(operation.Application) && !string.IsNullOrWhiteSpace(operation.Reason) &&
            !string.IsNullOrWhiteSpace(operation.RequiredPrivilege) && !string.IsNullOrWhiteSpace(operation.FutureRuleId));
        if (!longText) errors.Add("A plan row lacks the long-text content needed for trimming and tooltip validation.");

        window.ResponsivePage.ScrollViewer.ScrollToEnd();
        await window.Dispatcher.InvokeAsync(static () => { }, DispatcherPriority.Background);
        stopwatch.Stop();
        var responsive = window.ResponsivePage.ScrollViewer.ScrollableWidth <= 1d && stopwatch.Elapsed < TimeSpan.FromSeconds(15);
        if (!responsive) errors.Add($"The Program Connection Lock page overflowed horizontally or exceeded its responsiveness budget: {stopwatch.Elapsed}.");

        viewModel.SelectedPage = viewModel.NavigationItems[0];
        var status = baseline.Status == "Passed" && errors.Count == 0 ? "Passed" : "Failed";
        return new(
            1,
            status,
            baseline,
            planSmoke,
            exportPassed,
            readiness,
            virtualized,
            noMisleadingControls,
            banner,
            longText,
            responsive,
            errors);
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
