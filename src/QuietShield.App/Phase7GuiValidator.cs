using System.Diagnostics;
using System.Windows;
using System.Windows.Automation;
using System.Windows.Controls;
using System.Windows.Media;
using System.Windows.Threading;
using QuietShield.App.ViewModels;
using QuietShield.Core.ConnectionLock;

namespace QuietShield.App;

public sealed record Phase7GuiValidationResult(
    int SchemaVersion,
    string Status,
    Phase6GuiValidationResult Phase6Baseline,
    IReadOnlyList<string> UpdatedPages,
    bool ApplicationInventorySmokePassed,
    bool ProfileAndPolicySimulationPassed,
    bool PlannerSmokePassed,
    bool UpdatedTablesVirtualized,
    bool SimulationOnlyBannerPassed,
    bool MisleadingEnforcementControlsAbsent,
    bool UpdatedPagesResponsive,
    IReadOnlyList<string> Errors);

public static class Phase7GuiValidator
{
    private static readonly string[] UpdatedPageNames =
        { "Program Connection Lock", "Protection Profiles", "Schedules", "Compatibility Guard" };
    private static readonly string[] ProhibitedButtonNames = { "Apply", "Activate", "Enforce" };

    public static async Task<Phase7GuiValidationResult> ValidateAsync(MainWindow window, MainViewModel viewModel)
    {
        ArgumentNullException.ThrowIfNull(window);
        ArgumentNullException.ThrowIfNull(viewModel);
        var baseline = await Phase6GuiValidator.ValidateAsync(window, viewModel).ConfigureAwait(true);
        var errors = new List<string>();
        var stopwatch = Stopwatch.StartNew();
        var responsive = true;

        window.ApplyValidationSize(1024d, 640d);
        foreach (var pageName in UpdatedPageNames)
        {
            viewModel.SelectedPage = viewModel.NavigationItems.Single(page => page.Title.Equals(pageName, StringComparison.Ordinal));
            window.ResponsivePage.ScrollViewer.ScrollToTop();
            await window.Dispatcher.InvokeAsync(static () => { }, DispatcherPriority.Render);
            window.UpdateLayout();
            if (window.ResponsivePage.ScrollViewer.ScrollableWidth > 1d)
            {
                errors.Add($"{pageName} introduced horizontal scrolling at 1024x640.");
                responsive = false;
            }
            window.ResponsivePage.ScrollViewer.ScrollToEnd();
            await window.Dispatcher.InvokeAsync(static () => { }, DispatcherPriority.Background);
        }

        var namedLists = FindVisualChildren<ListBox>(window).Where(control =>
            control.Name is "ApplicationInventoryList" or "ProtectionProfileList" or "ScheduleTable" or "CompatibilityExclusionList" or "SafetyExemptionList").ToArray();
        var virtualized = namedLists.Length == 5 && namedLists.All(control =>
            VirtualizingPanel.GetIsVirtualizing(control) &&
            VirtualizingPanel.GetVirtualizationMode(control) == VirtualizationMode.Recycling);
        if (!virtualized) errors.Add("One or more Phase 7 inventory/profile/schedule/compatibility tables are not recycling-virtualized.");

        var prohibited = FindVisualChildren<Button>(window)
            .Select(static button => AutomationProperties.GetName(button).Length > 0 ? AutomationProperties.GetName(button) : button.Content?.ToString() ?? string.Empty)
            .Where(name => ProhibitedButtonNames.Any(prohibitedName => name.Equals(prohibitedName, StringComparison.OrdinalIgnoreCase)))
            .ToArray();
        var noMisleadingControls = prohibited.Length == 0;
        if (!noMisleadingControls) errors.Add("Misleading enforcement controls were visible: " + string.Join(", ", prohibited));

        var simulationBanner = viewModel.SimulationBanner.Contains("no Windows rule was applied", StringComparison.OrdinalIgnoreCase);
        if (!simulationBanner) errors.Add("The simulation-only banner is missing or unclear.");
        var inventorySmoke = viewModel.Applications.Count > 0 && viewModel.SelectedApplication is not null && !string.IsNullOrWhiteSpace(viewModel.IdentitySummary);
        if (!inventorySmoke) errors.Add("The read-only application inventory/identity smoke did not produce a selected application.");
        var profileSimulation = viewModel.ConnectionProfiles.Count is >= 1 and <= ProtectionProfileCatalog.MaximumEditableProfiles + 1 &&
                                viewModel.ConnectionProfiles.Count(static profile => profile.IsFixed) == 1 &&
                                !string.IsNullOrWhiteSpace(viewModel.SimulationDecision) &&
                                !string.IsNullOrWhiteSpace(viewModel.DecisionEvidence);
        if (!profileSimulation) errors.Add("The profile and policy simulation smoke failed.");
        var plannerSmoke = viewModel.PlannerSummary.Contains("Executable: False", StringComparison.Ordinal) &&
                           viewModel.PlannerSummary.Contains("Rollback steps:", StringComparison.Ordinal);
        if (!plannerSmoke) errors.Add("The read-only enforcement planner smoke did not prove a non-executable plan with rollback steps.");

        stopwatch.Stop();
        responsive = responsive && stopwatch.Elapsed < TimeSpan.FromSeconds(15);
        if (!responsive) errors.Add($"Updated-page validation exceeded the responsiveness budget or found layout errors: {stopwatch.Elapsed}.");
        viewModel.SelectedPage = viewModel.NavigationItems[0];
        var status = baseline.Status == "Passed" && errors.Count == 0 ? "Passed" : "Failed";
        return new Phase7GuiValidationResult(
            1,
            status,
            baseline,
            UpdatedPageNames,
            inventorySmoke,
            profileSimulation,
            plannerSmoke,
            virtualized,
            simulationBanner,
            noMisleadingControls,
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
