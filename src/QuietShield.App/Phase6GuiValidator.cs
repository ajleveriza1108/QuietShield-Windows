using System.Diagnostics;
using System.Windows;
using System.Windows.Automation;
using System.Windows.Controls;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Threading;
using QuietShield.App.ViewModels;
using QuietShield.Core.Presentation;

namespace QuietShield.App;

public sealed record GuiResolutionResult(string Resolution, bool Passed, int PagesChecked, IReadOnlyList<string> Errors);
public sealed record GuiScalingResult(int ScalingPercent, double EffectiveWidth, double EffectiveHeight, bool Passed);
public sealed record Phase6GuiValidationResult(
    int SchemaVersion,
    string Status,
    int PageCount,
    IReadOnlyList<string> Pages,
    IReadOnlyList<GuiResolutionResult> Resolutions,
    IReadOnlyList<GuiScalingResult> Scaling,
    double ActualDpiScaleX,
    double ActualDpiScaleY,
    bool MaximizedStatePassed,
    bool LongTextPassed,
    bool InventoryVirtualized,
    bool KeyboardNavigationPassed,
    bool UiResponsive,
    IReadOnlyList<string> Errors);

public static class Phase6GuiValidator
{
    private static readonly (double Width, double Height)[] Resolutions =
    {
        (1024d, 640d),
        (1366d, 768d),
        (1920d, 1080d)
    };

    private static readonly int[] ScalingLevels = { 100, 125, 150, 200 };

    public static async Task<Phase6GuiValidationResult> ValidateAsync(MainWindow window, MainViewModel viewModel)
    {
        ArgumentNullException.ThrowIfNull(window);
        ArgumentNullException.ThrowIfNull(viewModel);
        await window.Dispatcher.InvokeAsync(static () => { }, DispatcherPriority.Loaded);

        var allErrors = new List<string>();
        var results = new List<GuiResolutionResult>();
        var pages = viewModel.NavigationItems.ToArray();
        var stopwatch = Stopwatch.StartNew();

        foreach (var resolution in Resolutions)
        {
            window.ApplyValidationSize(resolution.Width, resolution.Height);
            var errors = await ValidateAllPagesAsync(window, viewModel, pages).ConfigureAwait(true);
            results.Add(new GuiResolutionResult($"{resolution.Width:0}x{resolution.Height:0}", errors.Count == 0, pages.Length, errors));
            allErrors.AddRange(errors.Select(error => $"{resolution.Width:0}x{resolution.Height:0}: {error}"));
        }

        window.WindowState = WindowState.Maximized;
        await window.Dispatcher.InvokeAsync(static () => { }, DispatcherPriority.Render);
        window.UpdateLayout();
        var maximizedErrors = ValidateCurrentLayout(window, "Maximized");
        var maximizedPassed = maximizedErrors.Count == 0;
        allErrors.AddRange(maximizedErrors);

        window.ApplyValidationSize(1024d, 640d);
        bool longTextPassed;
        using (viewModel.ApplyPhase6LongTextScenario())
        {
            var longTextErrors = new List<string>();
            foreach (var page in new[]
                     {
                         viewModel.SelectedPage,
                         pages.Single(static page => page.Title == "Program Connection Lock"),
                         pages.Single(static page => page.Title == "DNS Protection"),
                         pages.Single(static page => page.Title == "Settings")
                     })
            {
                viewModel.SelectedPage = page;
                await window.Dispatcher.InvokeAsync(static () => { }, DispatcherPriority.Render);
                window.UpdateLayout();
                var list = FindVisualChildren<ListView>(window).FirstOrDefault(control => control.Name == "ApplicationInventoryList" && control.IsVisible);
                if (list is not null && list.Items.Count > 0) list.ScrollIntoView(list.Items[0]);
                longTextErrors.AddRange(ValidateCurrentLayout(window, "Long text - " + page.Title));
            }
            longTextPassed = longTextErrors.Count == 0 && window.ResponsivePage.ScrollViewer.ScrollableWidth <= 1d;
            allErrors.AddRange(longTextErrors);
            if (!longTextPassed && longTextErrors.Count == 0) allErrors.Add("Long text: unexpected horizontal scrolling.");
        }

        var inventory = FindVisualChildren<ListView>(window).FirstOrDefault(list => list.Name == "ApplicationInventoryList");
        var inventoryVirtualized = inventory is not null &&
                                   VirtualizingPanel.GetIsVirtualizing(inventory) &&
                                   VirtualizingPanel.GetVirtualizationMode(inventory) == VirtualizationMode.Recycling;
        if (!inventoryVirtualized) allErrors.Add("Application inventory virtualization was not active.");

        var keyboardPassed = ValidateKeyboardReachability(window, allErrors);
        var dpi = VisualTreeHelper.GetDpi(window);
        var scaling = ScalingLevels.Select(level =>
        {
            var effective = ResponsiveLayout.GetEffectiveViewport(2048d, 1280d, level);
            return new GuiScalingResult(level, effective.Width, effective.Height,
                double.IsFinite(effective.Width) && double.IsFinite(effective.Height));
        }).ToArray();

        stopwatch.Stop();
        var responsive = stopwatch.Elapsed < TimeSpan.FromSeconds(15);
        if (!responsive) allErrors.Add($"GUI validation exceeded the responsiveness budget: {stopwatch.Elapsed}.");

        viewModel.SelectedPage = pages[0];
        window.WindowState = WindowState.Normal;
        var status = allErrors.Count == 0 && results.All(static result => result.Passed) &&
                     maximizedPassed && longTextPassed && inventoryVirtualized && keyboardPassed && responsive
            ? "Passed"
            : "Failed";
        return new Phase6GuiValidationResult(
            1, status, pages.Length, pages.Select(static page => page.Title).ToArray(), results, scaling,
            dpi.DpiScaleX, dpi.DpiScaleY, maximizedPassed, longTextPassed, inventoryVirtualized,
            keyboardPassed, responsive, allErrors);
    }

    private static async Task<List<string>> ValidateAllPagesAsync(
        MainWindow window,
        MainViewModel viewModel,
        IReadOnlyList<NavigationItem> pages)
    {
        var errors = new List<string>();
        foreach (var page in pages)
        {
            viewModel.SelectedPage = page;
            window.ResponsivePage.ScrollViewer.ScrollToTop();
            await window.Dispatcher.InvokeAsync(static () => { }, DispatcherPriority.Render);
            window.UpdateLayout();
            errors.AddRange(ValidateCurrentLayout(window, page.Title));
            window.ResponsivePage.ScrollViewer.ScrollToEnd();
            await window.Dispatcher.InvokeAsync(static () => { }, DispatcherPriority.Background);
            window.ResponsivePage.ScrollViewer.ScrollToTop();
        }
        return errors;
    }

    private static List<string> ValidateCurrentLayout(MainWindow window, string scenario)
    {
        var errors = new List<string>();
        var navigationBounds = GetBounds(window.NavigationArea, window.LayoutRoot);
        var pageBounds = GetBounds(window.PageArea, window.LayoutRoot);
        if (navigationBounds.IntersectsWith(pageBounds)) errors.Add($"{scenario}: navigation overlaps page content.");
        if (window.ResponsivePage.ActualWidth <= 0d || window.ResponsivePage.ActualHeight <= 0d) errors.Add($"{scenario}: page shell has no usable size.");
        if (window.ResponsivePage.ScrollViewer.ScrollableWidth > 1d) errors.Add($"{scenario}: page introduced horizontal scrolling.");

        foreach (var button in FindVisualChildren<Button>(window).Where(static button => button.IsVisible && button.IsEnabled))
        {
            if (button.ActualWidth < 32d || button.ActualHeight < 32d) errors.Add($"{scenario}: button '{GetAccessibleName(button)}' is too small or clipped.");
            if (string.IsNullOrWhiteSpace(GetAccessibleName(button))) errors.Add($"{scenario}: a visible button has no accessible name.");
        }
        var unreachable = GetUnreachableControls(window);
        if (unreachable.Length > 0)
        {
            errors.Add($"{scenario}: {unreachable.Length} visible interactive controls are outside the tab sequence ({FormatControls(unreachable)}). ");
        }
        return errors;
    }

    private static bool ValidateKeyboardReachability(MainWindow window, List<string> errors)
    {
        var interactive = GetInteractiveControls(window);
        var unreachable = GetUnreachableControls(window);
        if (interactive.Length == 0 || unreachable.Length > 0)
        {
            errors.Add($"Keyboard navigation: {unreachable.Length} of {interactive.Length} visible interactive controls are outside the tab sequence ({FormatControls(unreachable)}). ");
            return false;
        }
        return true;
    }

    private static Control[] GetInteractiveControls(MainWindow window) => FindVisualChildren<Control>(window)
        .Where(static control => control.IsVisible && control.IsEnabled && control.Focusable &&
                                 control is Button or TextBox or ComboBox or CheckBox or ListBox)
        .ToArray();

    private static Control[] GetUnreachableControls(MainWindow window) =>
        GetInteractiveControls(window).Where(static control => !KeyboardNavigation.GetIsTabStop(control)).ToArray();

    private static string FormatControls(IEnumerable<Control> controls) => string.Join(", ", controls.Select(control =>
        $"{control.GetType().Name}:{AutomationProperties.GetName(control)}"));

    private static string GetAccessibleName(Button button)
    {
        var automationName = AutomationProperties.GetName(button);
        if (!string.IsNullOrWhiteSpace(automationName)) return automationName;
        return button.Content?.ToString()?.Replace("_", string.Empty, StringComparison.Ordinal) ?? string.Empty;
    }

    private static Rect GetBounds(FrameworkElement element, Visual ancestor)
    {
        var origin = element.TransformToAncestor(ancestor).Transform(new Point(0d, 0d));
        return new Rect(origin, new Size(element.ActualWidth, element.ActualHeight));
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
