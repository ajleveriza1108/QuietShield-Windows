using System.Runtime.InteropServices;
using System.Text.Json;
using System.Text.RegularExpressions;
using QuietShield.Windows.Integration;

namespace QuietShield.Windows.Diagnostics;

public sealed record PrivacySafeDiagnosticSummary(
    string QuietShieldVersion,
    string WindowsVersion,
    string Architecture,
    string DotNetVersion,
    int DiscoverySuccessCount,
    int DiscoveryFailureCount,
    int ApplicationTotal,
    string PrimaryNetworkType,
    string NetworkCost,
    string NetworkCategory,
    IReadOnlyDictionary<string, int> AdapterTypes,
    IReadOnlyDictionary<string, bool> FirewallProfiles,
    int QuietShieldOwnedFirewallRuleCount,
    IReadOnlyDictionary<string, int> DnsModes,
    int DnsAdapterCount,
    IReadOnlyDictionary<string, int> ApplicationTypes,
    FilteringPlatformCapability? FilteringPlatform,
    ServiceStateSnapshot? Services,
    PowerStateSnapshot? Power,
    IReadOnlyList<string> RedactedErrors,
    DateTimeOffset CreatedAtUtc);

public interface IPrivacySafeDiagnosticExporter
{
    PrivacySafeDiagnosticSummary CreateSummary(ReadOnlyDiscoveryBundle bundle);
    Task ExportAsync(ReadOnlyDiscoveryBundle bundle, string destinationPath, CancellationToken cancellationToken);
}

public sealed partial class PrivacySafeDiagnosticExporter : IPrivacySafeDiagnosticExporter
{
    private static readonly JsonSerializerOptions SerializerOptions = new(JsonSerializerDefaults.General) { WriteIndented = true };

    public PrivacySafeDiagnosticSummary CreateSummary(ReadOnlyDiscoveryBundle bundle)
    {
        ArgumentNullException.ThrowIfNull(bundle);
        var adapterTypes = bundle.Network?.Adapters.GroupBy(static item => item.Kind.ToString())
            .ToDictionary(static group => group.Key, static group => group.Count(), StringComparer.Ordinal) ?? new Dictionary<string, int>();
        var firewallProfiles = bundle.Firewall?.Profiles.ToDictionary(
            static item => item.Profile.ToString(), static item => item.Enabled, StringComparer.Ordinal) ?? new Dictionary<string, bool>();
        var dnsModes = bundle.Dns?.Adapters.GroupBy(static item => item.Mode.ToString())
            .ToDictionary(static group => group.Key, static group => group.Count(), StringComparer.Ordinal) ?? new Dictionary<string, int>();
        var applicationTypes = bundle.Applications.GroupBy(static item => item.ApplicationType.ToString())
            .ToDictionary(static group => group.Key, static group => group.Count(), StringComparer.Ordinal);
        var errors = bundle.Activity.Where(static item => !item.Succeeded).Select(static item => Redact(item.Message)).ToArray();

        return new PrivacySafeDiagnosticSummary(
            "0.4.0",
            Environment.OSVersion.VersionString,
            RuntimeInformation.OSArchitecture.ToString(),
            Environment.Version.ToString(),
            bundle.Activity.Count(static item => item.Succeeded),
            bundle.Activity.Count(static item => !item.Succeeded),
            bundle.Applications.Count,
            bundle.Network?.PrimaryKind.ToString() ?? "Unknown",
            bundle.Network?.Cost.ToString() ?? "Unknown",
            bundle.Network?.Category.ToString() ?? "Unknown",
            adapterTypes,
            firewallProfiles,
            bundle.Firewall?.QuietShieldOwnedRuleCount ?? 0,
            dnsModes,
            bundle.Dns?.Adapters.Count ?? 0,
            applicationTypes,
            bundle.FilteringPlatform,
            bundle.Services,
            bundle.Power,
            errors,
            DateTimeOffset.UtcNow);
    }

    public async Task ExportAsync(ReadOnlyDiscoveryBundle bundle, string destinationPath, CancellationToken cancellationToken)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(destinationPath);
        var directory = Path.GetDirectoryName(destinationPath);
        if (string.IsNullOrWhiteSpace(directory)) throw new ArgumentException("A diagnostic destination directory is required.", nameof(destinationPath));
        Directory.CreateDirectory(directory);
        await using var stream = new FileStream(destinationPath, FileMode.Create, FileAccess.Write, FileShare.None, 81920, FileOptions.Asynchronous);
        await JsonSerializer.SerializeAsync(stream, CreateSummary(bundle), SerializerOptions, cancellationToken).ConfigureAwait(false);
    }

    public static string Redact(string value)
    {
        if (string.IsNullOrWhiteSpace(value)) return string.Empty;
        var redacted = UserPathRegex().Replace(value, @"C:\Users\[redacted]");
        redacted = Ipv4Regex().Replace(redacted, "[ip-redacted]");
        redacted = Ipv6Regex().Replace(redacted, "[ip-redacted]");
        redacted = MacAddressRegex().Replace(redacted, "[mac-redacted]");
        redacted = TokenRegex().Replace(redacted, "$1[redacted]");
        var profile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        if (!string.IsNullOrWhiteSpace(profile)) redacted = redacted.Replace(profile, "[user-profile]", StringComparison.OrdinalIgnoreCase);
        if (!string.IsNullOrWhiteSpace(Environment.UserName)) redacted = redacted.Replace(Environment.UserName, "[user]", StringComparison.OrdinalIgnoreCase);
        return redacted;
    }

    [GeneratedRegex(@"(?i)C:\\Users\\[^\\\s]+")]
    private static partial Regex UserPathRegex();
    [GeneratedRegex(@"(?<!\d)(?:\d{1,3}\.){3}\d{1,3}(?!\d)")]
    private static partial Regex Ipv4Regex();
    [GeneratedRegex(@"(?i)(?<![0-9a-f:])(?:[0-9a-f]{0,4}:){2,7}[0-9a-f]{0,4}(?![0-9a-f:])")]
    private static partial Regex Ipv6Regex();
    [GeneratedRegex(@"(?i)(?<![0-9a-f])(?:[0-9a-f]{2}[:-]){5}[0-9a-f]{2}(?![0-9a-f])")]
    private static partial Regex MacAddressRegex();
    [GeneratedRegex(@"(?i)\b(token|password|secret|license|licence|key)\s*[:=]\s*([^\s,;]+)")]
    private static partial Regex TokenRegex();
}
