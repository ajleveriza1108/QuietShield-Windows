// QuietShield Backend Pack 5-8 R1
using System.Globalization;

namespace QuietShield.Core.FinalBackends;

public enum PrivateBrowserMode
{
    Standard = 0,
    Incognito = 1
}

public enum BrowserNavigationAction
{
    Allow = 0,
    Block = 1
}

public sealed record PrivateBrowserPolicy(
    bool RequireHttps,
    bool BlockCredentialInUrl,
    bool BlockPrivateNetworkDestinations,
    bool BlockKnownTrackerHosts,
    IReadOnlyList<string> BlockedHosts,
    IReadOnlyList<string> TrackerHosts);

public sealed record BrowserNavigationDecision(
    BrowserNavigationAction Action,
    Uri Uri,
    string Reason,
    bool TrackerMatched,
    bool PrivateNetworkMatched,
    bool CredentialMatched);

public static class PrivateBrowserNavigationPolicy
{
    private static readonly IdnMapping Idn = new();

    public static BrowserNavigationDecision Evaluate(
        PrivateBrowserPolicy policy,
        Uri destination)
    {
        ArgumentNullException.ThrowIfNull(policy);
        ArgumentNullException.ThrowIfNull(destination);

        if (!destination.IsAbsoluteUri)
        {
            return new(BrowserNavigationAction.Block, destination, "Relative navigation is not allowed.", false, false, false);
        }

        if (!destination.Scheme.Equals(Uri.UriSchemeHttp, StringComparison.OrdinalIgnoreCase) &&
            !destination.Scheme.Equals(Uri.UriSchemeHttps, StringComparison.OrdinalIgnoreCase))
        {
            return new(BrowserNavigationAction.Block, destination, "Only HTTP and HTTPS navigation is supported.", false, false, false);
        }

        if (policy.RequireHttps &&
            !destination.Scheme.Equals(Uri.UriSchemeHttps, StringComparison.OrdinalIgnoreCase))
        {
            return new(BrowserNavigationAction.Block, destination, "Private Browser policy requires HTTPS.", false, false, false);
        }

        var credentialMatched =
            policy.BlockCredentialInUrl &&
            !string.IsNullOrWhiteSpace(destination.UserInfo);

        if (credentialMatched)
        {
            return new(BrowserNavigationAction.Block, destination, "Credentials embedded in a URL are blocked.", false, false, true);
        }

        var host = NormalizeHost(destination.Host);

        if (policy.BlockedHosts.Any(pattern => HostMatches(host, pattern)))
        {
            return new(BrowserNavigationAction.Block, destination, "Host is on the Private Browser blocklist.", false, false, false);
        }

        var trackerMatched =
            policy.BlockKnownTrackerHosts &&
            policy.TrackerHosts.Any(pattern => HostMatches(host, pattern));

        if (trackerMatched)
        {
            return new(BrowserNavigationAction.Block, destination, "Known tracker host was blocked.", true, false, false);
        }

        var privateNetworkMatched =
            policy.BlockPrivateNetworkDestinations &&
            WebsiteSafetyEngine.IsPrivateOrLoopbackHost(host);

        if (privateNetworkMatched)
        {
            return new(BrowserNavigationAction.Block, destination, "Private or loopback network destination was blocked.", false, true, false);
        }

        return new(BrowserNavigationAction.Allow, destination, "Navigation is allowed by the Private Browser policy.", false, false, false);
    }

    private static string NormalizeHost(string host)
    {
        var normalized = host.Trim().TrimEnd('.').ToLowerInvariant();
        return Idn.GetAscii(normalized).ToLowerInvariant();
    }

    private static bool HostMatches(string host, string pattern)
    {
        var normalized = pattern.Trim().TrimEnd('.').ToLowerInvariant();
        if (normalized.StartsWith("*.", StringComparison.Ordinal))
        {
            var suffix = normalized[2..];
            return host.EndsWith("." + suffix, StringComparison.Ordinal);
        }

        return host.Equals(normalized, StringComparison.Ordinal) ||
               host.EndsWith("." + normalized, StringComparison.Ordinal);
    }
}

public sealed record PrivateBrowserCookie(
    string Name,
    string Value,
    string Host,
    DateTimeOffset? ExpiresAtUtc);

public sealed class PrivateBrowserSession
{
    private readonly object _sync = new();
    private readonly List<Uri> _history = new();
    private readonly Dictionary<string, PrivateBrowserCookie> _cookies =
        new(StringComparer.Ordinal);
    private bool _closed;

    public PrivateBrowserSession(
        PrivateBrowserMode mode,
        PrivateBrowserPolicy policy)
    {
        Mode = mode;
        Policy = policy ?? throw new ArgumentNullException(nameof(policy));
    }

    public PrivateBrowserMode Mode { get; }
    public PrivateBrowserPolicy Policy { get; }

    public BrowserNavigationDecision Navigate(Uri destination)
    {
        lock (_sync)
        {
            EnsureOpen();
            var decision = PrivateBrowserNavigationPolicy.Evaluate(Policy, destination);

            if (decision.Action == BrowserNavigationAction.Allow)
            {
                _history.Add(destination);
            }

            return decision;
        }
    }

    public void SetCookie(PrivateBrowserCookie cookie)
    {
        ArgumentNullException.ThrowIfNull(cookie);

        lock (_sync)
        {
            EnsureOpen();
            var key = cookie.Host.Trim().ToLowerInvariant() + "|" + cookie.Name;
            _cookies[key] = cookie;
        }
    }

    public List<Uri> GetHistorySnapshot()
    {
        lock (_sync)
        {
            return new List<Uri>(_history);
        }
    }

    public List<PrivateBrowserCookie> GetCookieSnapshot()
    {
        lock (_sync)
        {
            return new List<PrivateBrowserCookie>(_cookies.Values);
        }
    }

    public void Close()
    {
        lock (_sync)
        {
            if (_closed)
            {
                return;
            }

            if (Mode == PrivateBrowserMode.Incognito)
            {
                _history.Clear();
                _cookies.Clear();
            }

            _closed = true;
        }
    }

    private void EnsureOpen()
    {
        if (_closed)
        {
            throw new InvalidOperationException("Private Browser session is closed.");
        }
    }
}
