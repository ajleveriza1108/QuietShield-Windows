using System.Net;
using System.Net.NetworkInformation;
using System.Text.Json;
using QuietShield.Windows.Discovery;

namespace QuietShield.Windows.Dns;

public sealed record DnsRehearsalReadinessSnapshot(
    bool Ready,
    string Readiness,
    string ActiveAdapter,
    string Port53Availability,
    string OriginalDnsBackupStatus,
    string WatchdogReadiness,
    string LastRehearsalResult);

public interface IDnsRehearsalReadinessDiscovery
{
    Task<DnsRehearsalReadinessSnapshot> DiscoverAsync(CancellationToken cancellationToken);
}

public interface IDnsListenerSnapshotSource
{
    IReadOnlyList<IPEndPoint> GetUdpListeners();
    IReadOnlyList<IPEndPoint> GetTcpListeners();
}

public sealed class SystemDnsListenerSnapshotSource : IDnsListenerSnapshotSource
{
    public IReadOnlyList<IPEndPoint> GetUdpListeners() => IPGlobalProperties.GetIPGlobalProperties().GetActiveUdpListeners();
    public IReadOnlyList<IPEndPoint> GetTcpListeners() => IPGlobalProperties.GetIPGlobalProperties().GetActiveTcpListeners();
}

public static class DnsPort53ReadinessEvaluator
{
    public static bool IsAvailable(IDnsListenerSnapshotSource source)
    {
        ArgumentNullException.ThrowIfNull(source);
        return !source.GetUdpListeners().Concat(source.GetTcpListeners()).Any(static endpoint => endpoint.Port == 53);
    }
}

public sealed class ReadOnlyDnsRehearsalReadinessDiscovery(
    IPowerShellJsonRunner runner,
    IDnsListenerSnapshotSource listenerSource) : IDnsRehearsalReadinessDiscovery
{
    private const string AdapterScript = """
        $candidates = @(
            Get-NetAdapter -Physical -ErrorAction Stop | ForEach-Object {
                $kind = if ([string]$_.PhysicalMediaType -ceq 'Native 802.11' -and [int]$_.InterfaceType -eq 71) { 'WiFi' }
                        elseif ([string]$_.PhysicalMediaType -ceq '802.3' -and [int]$_.InterfaceType -eq 6) { 'Ethernet' }
                        else { 'Other' }
                if ([string]$_.Status -ceq 'Up' -and [bool]$_.HardwareInterface -and -not [bool]$_.Virtual -and @('WiFi','Ethernet') -contains $kind) {
                    [pscustomobject]@{ Kind = $kind; InterfaceGuid = ([Guid]$_.InterfaceGuid).ToString('D'); InterfaceIndex = [int]$_.InterfaceIndex }
                }
            }
        )
        [pscustomobject]@{ Candidates = @($candidates) } | ConvertTo-Json -Depth 4 -Compress
        """;

    public async Task<DnsRehearsalReadinessSnapshot> DiscoverAsync(CancellationToken cancellationToken)
    {
        var adapterResult = await runner.RunAsync(AdapterScript, cancellationToken).ConfigureAwait(false);
        if (adapterResult.ExitCode != 0) return Unavailable("Read-only physical-adapter discovery failed.");

        int candidateCount;
        string adapterStatus;
        try
        {
            using var document = JsonDocument.Parse(adapterResult.StandardOutput);
            var candidates = document.RootElement.GetProperty("Candidates");
            candidateCount = candidates.GetArrayLength();
            adapterStatus = candidateCount == 1
                ? FormatAdapter(candidates[0])
                : candidateCount == 0
                    ? "No active supported physical Wi-Fi or Ethernet adapter."
                    : $"Ambiguous: {candidateCount} active supported physical adapters.";
        }
        catch (Exception exception) when (exception is JsonException or KeyNotFoundException or InvalidOperationException)
        {
            return Unavailable("Read-only physical-adapter discovery returned invalid data.");
        }

        var portAvailable = DnsPort53ReadinessEvaluator.IsAvailable(listenerSource);
        var watchdogAvailable = FindRepositoryFile(Path.Combine("artifacts", "bin", "QuietShield.DnsWatchdog", "Release", "net10.0-windows", "QuietShield.DnsWatchdog.exe"));
        var ready = candidateCount == 1 && portAvailable && watchdogAvailable;
        return new DnsRehearsalReadinessSnapshot(
            ready,
            ready ? "Ready for the separate, explicitly elevated rehearsal command." : "Not ready; no DNS change is available from this app.",
            adapterStatus,
            portAvailable ? "Available for temporary loopback UDP/TCP binding." : "Unavailable; an existing listener uses port 53.",
            "Created and validated only by the separately approved rehearsal command.",
            watchdogAvailable ? "Independent watchdog build output is available." : "Independent watchdog Release build output is not available.",
            ReadLastResult());
    }

    private static string FormatAdapter(JsonElement candidate) =>
        $"{candidate.GetProperty("Kind").GetString()} — Interface {candidate.GetProperty("InterfaceIndex").GetInt32()}, {candidate.GetProperty("InterfaceGuid").GetString()}";

    private static DnsRehearsalReadinessSnapshot Unavailable(string status) => new(
        false, status, "Unavailable", "Not evaluated", "Not created", "Not evaluated", "No rehearsal result available.");

    private static string ReadLastResult()
    {
        var root = FindRepositoryRoot();
        if (root is null) return "No rehearsal result available.";
        var rehearsalRoot = Path.Combine(root, "artifacts", "dns-rehearsal");
        if (!Directory.Exists(rehearsalRoot)) return "No rehearsal result available.";
        var result = Directory.EnumerateFiles(rehearsalRoot, "rehearsal-result.json", SearchOption.AllDirectories)
            .OrderByDescending(File.GetLastWriteTimeUtc)
            .FirstOrDefault();
        if (result is null) return "No rehearsal result available.";
        try
        {
            using var document = JsonDocument.Parse(File.ReadAllText(result));
            var status = document.RootElement.GetProperty("status").GetString() ?? "Unknown";
            return $"Last retained command result: {status}.";
        }
        catch (Exception exception) when (exception is IOException or JsonException or UnauthorizedAccessException or KeyNotFoundException or InvalidOperationException)
        {
            return "The last retained rehearsal result could not be read.";
        }
    }

    private static bool FindRepositoryFile(string relativePath)
    {
        var root = FindRepositoryRoot();
        return root is not null && File.Exists(Path.Combine(root, relativePath));
    }

    private static string? FindRepositoryRoot()
    {
        var directory = new DirectoryInfo(AppContext.BaseDirectory);
        while (directory is not null)
        {
            if (File.Exists(Path.Combine(directory.FullName, "QuietShield.sln"))) return directory.FullName;
            directory = directory.Parent;
        }
        return null;
    }
}
