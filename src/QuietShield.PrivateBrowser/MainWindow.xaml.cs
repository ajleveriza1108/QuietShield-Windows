// QuietShield Backend Runtime Completion R4.0
using System.IO;
using System.Windows;
using Microsoft.Web.WebView2.Core;
using QuietShield.Core.FinalBackends;
using QuietShield.Core.ServiceFoundation;

namespace QuietShield.PrivateBrowser;

public partial class MainWindow : Window
{
    private static readonly string[] AdSuffixes =
    [
        "doubleclick.net", "googleadservices.com", "googlesyndication.com",
        "amazon-adsystem.com", "adnxs.com", "adsrvr.org", "pubmatic.com",
        "rubiconproject.com", "openx.net", "criteo.com", "taboola.com", "outbrain.com"
    ];

    private static readonly string[] TrackerSuffixes =
    [
        "google-analytics.com", "analytics.google.com", "googletagmanager.com",
        "hotjar.com", "clarity.ms", "scorecardresearch.com", "quantserve.com",
        "segment.com", "mixpanel.com", "amplitude.com",
        "connect.facebook.net", "bat.bing.com"
    ];

    private readonly bool _smoke;
    private readonly bool _incognito;
    private readonly string _userDataFolder;
    private readonly PrivateBrowserPolicy _policy;
    private readonly NamedPipeQuietShieldServiceClient _serviceClient;

    public MainWindow(bool smoke, bool incognito)
    {
        _smoke = smoke;
        _incognito = incognito;

        _userDataFolder = incognito
            ? Path.Combine(
                Path.GetTempPath(),
                "QuietShield",
                "PrivateBrowser",
                Guid.NewGuid().ToString("N"))
            : Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
                "QuietShield",
                "PrivateBrowser",
                "WebView2");

        _policy = new(
            RequireHttps: false,
            BlockCredentialInUrl: true,
            BlockPrivateNetworkDestinations: true,
            BlockKnownTrackerHosts: true,
            BlockedHosts:
                AdSuffixes
                    .Concat(AdSuffixes.Select(static value => "*." + value))
                    .ToArray(),
            TrackerHosts:
                TrackerSuffixes
                    .Concat(TrackerSuffixes.Select(static value => "*." + value))
                    .ToArray());

        _serviceClient = new NamedPipeQuietShieldServiceClient(
            QuietShieldServiceProtocol.ProductionPipeName,
            TimeSpan.FromSeconds(2),
            currentUserOnly: false);

        InitializeComponent();
        Loaded += OnLoaded;
        Closed += OnClosed;
    }

    private async void OnLoaded(object sender, RoutedEventArgs e)
    {
        try
        {
            var environment =
                await CoreWebView2Environment.CreateAsync(
                    browserExecutableFolder: null,
                    userDataFolder: _userDataFolder).ConfigureAwait(true);

            await Browser.EnsureCoreWebView2Async(environment).ConfigureAwait(true);

            Browser.CoreWebView2.NavigationStarting += OnNavigationStarting;
            Browser.CoreWebView2.AddWebResourceRequestedFilter(
                "*",
                CoreWebView2WebResourceContext.All);
            Browser.CoreWebView2.WebResourceRequested += OnWebResourceRequested;
            Browser.CoreWebView2.Settings.AreDevToolsEnabled = true;
            Browser.CoreWebView2.Settings.AreDefaultContextMenusEnabled = true;
            Browser.CoreWebView2.Settings.IsStatusBarEnabled = false;
            Browser.CoreWebView2.Navigate(AddressBox.Text);

            if (_smoke)
            {
                await Task.Delay(900).ConfigureAwait(true);
                Close();
            }
        }
        catch (WebView2RuntimeNotFoundException exception) { HandleStartupFailure(exception); }
        catch (InvalidOperationException exception) { HandleStartupFailure(exception); }
        catch (ArgumentException exception) { HandleStartupFailure(exception); }
        catch (System.Runtime.InteropServices.COMException exception) { HandleStartupFailure(exception); }
        catch (IOException exception) { HandleStartupFailure(exception); }
        catch (UnauthorizedAccessException exception) { HandleStartupFailure(exception); }
    }

    private void OnWebResourceRequested(
        object? sender,
        CoreWebView2WebResourceRequestedEventArgs args)
    {
        if (!Uri.TryCreate(args.Request.Uri, UriKind.Absolute, out var uri))
            return;

        var category = ClassifyHost(uri.Host);
        if (category is null)
            return;

        args.Response = Browser.CoreWebView2.Environment.CreateWebResourceResponse(
            new MemoryStream(),
            204,
            "No Content",
            "Cache-Control: no-store\r\nContent-Type: text/plain");

        _ = ReportBlockAsync(uri.Host, category);
    }

    private async Task ReportBlockAsync(string host, string category)
    {
        try
        {
            await _serviceClient.SendAsync(
                ServiceMessageKind.ReportPrivateBrowserBlockEvent,
                new PrivateBrowserBlockEventR40(host, category, DateTimeOffset.UtcNow),
                CancellationToken.None).ConfigureAwait(false);
        }
        catch (Exception exception) when (
            exception is IOException or TimeoutException or
            InvalidDataException or OperationCanceledException)
        {
        }
    }

    private static string? ClassifyHost(string host)
    {
        var normalized = host.Trim().TrimEnd('.').ToLowerInvariant();
        if (Matches(normalized, AdSuffixes))
            return "ad";
        if (Matches(normalized, TrackerSuffixes))
            return "tracker";
        return null;
    }

    private static bool Matches(string host, IReadOnlyList<string> suffixes)
    {
        foreach (var suffix in suffixes)
        {
            if (string.Equals(host, suffix, StringComparison.Ordinal) ||
                host.EndsWith("." + suffix, StringComparison.Ordinal))
                return true;
        }
        return false;
    }

    private void HandleStartupFailure(Exception exception)
    {
        if (_smoke)
        {
            Console.Error.WriteLine(exception);
            Environment.ExitCode = 2;
            Close();
            return;
        }

        MessageBox.Show(
            exception.Message,
            "QuietShield Private Browser startup",
            MessageBoxButton.OK,
            MessageBoxImage.Error);
    }

    private void OnNavigationStarting(
        object? sender,
        CoreWebView2NavigationStartingEventArgs args)
    {
        if (!Uri.TryCreate(args.Uri, UriKind.Absolute, out var uri))
        {
            args.Cancel = true;
            return;
        }

        var decision = PrivateBrowserNavigationPolicy.Evaluate(_policy, uri);

        if (decision.Action == BrowserNavigationAction.Block)
        {
            args.Cancel = true;
            Title = "Blocked - " + decision.Reason;
        }
        else
        {
            AddressBox.Text = uri.AbsoluteUri;
            Title = _incognito
                ? "QuietShield Private Browser - Incognito"
                : "QuietShield Private Browser";
        }
    }

    private void OnBackClick(object sender, RoutedEventArgs e)
    {
        if (Browser.CanGoBack)
            Browser.GoBack();
    }

    private void OnGoClick(object sender, RoutedEventArgs e)
    {
        if (Browser.CoreWebView2 is null)
            return;

        var value = AddressBox.Text.Trim();
        if (!value.Contains("://", StringComparison.Ordinal))
            value = "https://" + value;

        Browser.CoreWebView2.Navigate(value);
    }

    private void OnClosed(object? sender, EventArgs e)
    {
        if (Browser.CoreWebView2 is not null)
        {
            Browser.CoreWebView2.NavigationStarting -= OnNavigationStarting;
            Browser.CoreWebView2.WebResourceRequested -= OnWebResourceRequested;
        }

        Browser.Dispose();

        if (!_incognito)
            return;

        try
        {
            if (Directory.Exists(_userDataFolder))
                Directory.Delete(_userDataFolder, recursive: true);
        }
        catch (IOException) { }
        catch (UnauthorizedAccessException) { }
    }
}
