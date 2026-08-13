// QuietShield Backend Pack 5-8 R1
using System.Globalization;
using System.Net;
using System.Net.Sockets;

namespace QuietShield.Core.FinalBackends;

public enum WebsiteRiskLevel
{
    Low = 0,
    Caution = 1,
    High = 2,
    Block = 3
}

public sealed record WebsiteSafetyReport(
    Uri Uri,
    WebsiteRiskLevel Risk,
    IReadOnlyList<string> Signals,
    bool ShouldBlock);

public static class WebsiteSafetyEngine
{
    private static readonly IdnMapping Idn = new();

    public static WebsiteSafetyReport Evaluate(
        Uri uri,
        IReadOnlyList<string>? explicitlyBlockedHosts = null)
    {
        ArgumentNullException.ThrowIfNull(uri);

        var signals = new List<string>();
        var risk = WebsiteRiskLevel.Low;

        if (!uri.IsAbsoluteUri ||
            (!uri.Scheme.Equals(Uri.UriSchemeHttp, StringComparison.OrdinalIgnoreCase) &&
             !uri.Scheme.Equals(Uri.UriSchemeHttps, StringComparison.OrdinalIgnoreCase)))
        {
            signals.Add("Unsupported or non-web URI scheme.");
            return new(uri, WebsiteRiskLevel.Block, signals, true);
        }

        if (!string.IsNullOrWhiteSpace(uri.UserInfo))
        {
            signals.Add("URL contains embedded credentials.");
            risk = Max(risk, WebsiteRiskLevel.High);
        }

        if (uri.Scheme.Equals(Uri.UriSchemeHttp, StringComparison.OrdinalIgnoreCase))
        {
            signals.Add("Connection is not HTTPS.");
            risk = Max(risk, WebsiteRiskLevel.Caution);
        }

        var host = NormalizeHost(uri.Host);

        if (explicitlyBlockedHosts is not null &&
            explicitlyBlockedHosts.Any(pattern => HostMatches(host, pattern)))
        {
            signals.Add("Host is explicitly blocked.");
            return new(uri, WebsiteRiskLevel.Block, signals, true);
        }

        if (host.Contains("xn--", StringComparison.OrdinalIgnoreCase))
        {
            signals.Add("Internationalized/punycode hostname requires additional scrutiny.");
            risk = Max(risk, WebsiteRiskLevel.Caution);
        }

        if (IsPrivateOrLoopbackHost(host))
        {
            signals.Add("Destination is a loopback/private literal.");
            risk = Max(risk, WebsiteRiskLevel.Caution);
        }

        if (LooksLikeExecutableDownload(uri.AbsolutePath))
        {
            signals.Add("URL path resembles an executable/script download.");
            risk = Max(risk, WebsiteRiskLevel.Caution);
        }

        return new(uri, risk, signals, risk == WebsiteRiskLevel.Block);
    }

    public static bool IsPrivateOrLoopbackHost(string host)
    {
        if (host.Equals("localhost", StringComparison.OrdinalIgnoreCase))
        {
            return true;
        }

        if (!IPAddress.TryParse(host, out var address))
        {
            return false;
        }

        if (IPAddress.IsLoopback(address))
        {
            return true;
        }

        if (address.AddressFamily == AddressFamily.InterNetwork)
        {
            var bytes = address.GetAddressBytes();
            return bytes[0] == 10 ||
                   bytes[0] == 127 ||
                   (bytes[0] == 169 && bytes[1] == 254) ||
                   (bytes[0] == 172 && bytes[1] is >= 16 and <= 31) ||
                   (bytes[0] == 192 && bytes[1] == 168);
        }

        if (address.AddressFamily == AddressFamily.InterNetworkV6)
        {
            return address.IsIPv6LinkLocal ||
                   address.IsIPv6SiteLocal ||
                   address.Equals(IPAddress.IPv6Loopback);
        }

        return false;
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
            return host.EndsWith("." + normalized[2..], StringComparison.Ordinal);
        }

        return host.Equals(normalized, StringComparison.Ordinal) ||
               host.EndsWith("." + normalized, StringComparison.Ordinal);
    }

    private static WebsiteRiskLevel Max(WebsiteRiskLevel left, WebsiteRiskLevel right) =>
        left >= right ? left : right;

    private static bool LooksLikeExecutableDownload(string path)
    {
        var extension = Path.GetExtension(path).ToLowerInvariant();
        return extension is
            ".exe" or ".msi" or ".msix" or ".appx" or
            ".bat" or ".cmd" or ".ps1" or ".vbs" or ".js" or
            ".scr" or ".com" or ".dll";
    }
}
