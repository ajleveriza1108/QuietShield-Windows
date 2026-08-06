using QuietShield.Windows.Integration;

namespace QuietShield.App.ViewModels;

public sealed partial class MainViewModel
{
    private static readonly string[] Phase6ValidationDiscoverySources = { "Phase6GuiValidation" };

    internal IDisposable ApplyPhase6LongTextScenario()
    {
        var previousPage = SelectedPage;
        var previousApplication = SelectedApplication;
        var previousNetwork = NetworkSummary;
        var previousDns = DnsSummary;
        var previousStatus = LastActionStatus;
        var longApplication = new ApplicationListItem(new InstalledApplicationInfo(
            "phase6-long-value",
            "A deliberately long translated-style application name used to validate trimming, tooltips, responsive columns, and keyboard reachability without changing an installed application",
            "A deliberately long publisher organization name used only by the local Phase 6 GUI validation process",
            "2026.8.6-validation",
            null,
            null,
            InstalledApplicationType.Win32,
            null,
            false,
            false,
            Phase6ValidationDiscoverySources));
        var longPage = new NavigationItem(
            "A deliberately long translated-style navigation and page title used for responsive layout validation",
            "This deliberately long description verifies that the reusable page shell wraps translated-style explanatory text without clipping or horizontal scrolling.",
            "\uE946",
            "LAYOUT TEST",
            false);

        Applications.Insert(0, longApplication);
        NavigationItems.Add(longPage);
        NetworkSummary = "A deliberately long network description verifies that read-only status text wraps cleanly across narrow layouts and remains understandable without exposing private adapter details.";
        DnsSummary = "A deliberately long DNS description verifies wrapping, card resizing, and safe presentation of an inactive DNS foundation without implying that activation or enforcement succeeded.";
        LastActionStatus = "A deliberately long validation message verifies that complete error and status text remains readable, wraps across multiple lines, and is never communicated by color alone.";
        SelectedApplication = longApplication;
        SelectedPage = longPage;

        return new DelegateDisposable(() =>
        {
            Applications.Remove(longApplication);
            NavigationItems.Remove(longPage);
            NetworkSummary = previousNetwork;
            DnsSummary = previousDns;
            LastActionStatus = previousStatus;
            SelectedApplication = previousApplication;
            SelectedPage = previousPage;
        });
    }

    private sealed class DelegateDisposable(Action dispose) : IDisposable
    {
        private Action? _dispose = dispose;

        public void Dispose() => Interlocked.Exchange(ref _dispose, null)?.Invoke();
    }
}
