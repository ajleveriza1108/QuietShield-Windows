using System.Diagnostics;
using System.Text.Json;
using QuietShield.Core.Dns;

namespace QuietShield.DnsWatchdog;

public static class Program
{
    public static async Task<int> Main(string[] args)
    {
        WatchdogOptions options;
        try { options = WatchdogOptions.Parse(args); }
        catch (Exception exception) when (exception is ArgumentException or FormatException)
        {
            Console.Error.WriteLine(exception.Message);
            return 2;
        }

        try
        {
            var validation = DnsRehearsalBackupSerializer.DeserializeAndValidate(await File.ReadAllTextAsync(options.BackupPath).ConfigureAwait(false));
            if (!validation.Succeeded) throw new InvalidDataException(validation.Status);
            AppendLog(options.LogPath, "WatchdogStarted", "Validated rehearsal backup; independent monitoring started.");

            int? hostProcessId = null;
            DateTimeOffset? hostReadyObservedUtc = null;
            while (true)
            {
                var armed = File.Exists(options.ArmedPath);
                if (!armed && File.Exists(options.CancelPath))
                {
                    AppendLog(options.LogPath, "WatchdogCancelledBeforeArming", "The orchestrator stopped before any DNS change window was armed.");
                    return 0;
                }
                var parentAlive = IsProcessAlive(options.OrchestratorProcessId);
                if (hostProcessId is null && File.Exists(options.HostReadyPath))
                {
                    hostProcessId = ReadHostProcessId(options.HostReadyPath);
                    if (hostProcessId is not null) hostReadyObservedUtc = DateTimeOffset.UtcNow;
                }
                var heartbeatStarted = File.Exists(options.HeartbeatPath);
                DateTimeOffset? lastHeartbeat = heartbeatStarted
                    ? new DateTimeOffset(File.GetLastWriteTimeUtc(options.HeartbeatPath), TimeSpan.Zero)
                    : hostReadyObservedUtc;
                var connectivityCompleted = false;
                var connectivityHealthy = true;
                if (armed && hostProcessId is not null)
                {
                    connectivityCompleted = true;
                    connectivityHealthy = await TestConnectivityAsync().ConfigureAwait(false);
                }

                var decision = DnsWatchdogDecisionEvaluator.Evaluate(new DnsWatchdogObservation(
                    armed,
                    File.Exists(options.RestoredPath),
                    DateTimeOffset.UtcNow,
                    options.DeadlineUtc,
                    heartbeatStarted || hostReadyObservedUtc is not null,
                    lastHeartbeat,
                    TimeSpan.FromSeconds(8),
                    hostProcessId is not null,
                    hostProcessId is not null && IsProcessAlive(hostProcessId.Value),
                    parentAlive,
                    connectivityCompleted,
                    connectivityHealthy,
                    File.Exists(options.RollbackRequestPath)));

                if (decision.Stop) return 0;
                if (decision.RestoreRequired)
                {
                    AppendLog(options.LogPath, "RollbackTriggered", decision.Trigger + ": " + decision.Status);
                    var restored = await RunRestoreAsync(options, decision.Trigger).ConfigureAwait(false);
                    if (!restored) return 1;
                    WriteJsonAtomically(options.RestoredPath, new
                    {
                        schemaVersion = 1,
                        productMarker = "QuietShield",
                        purpose = "DnsRehearsalRestored",
                        trigger = decision.Trigger.ToString(),
                        restoredAtUtc = DateTimeOffset.UtcNow
                    });
                    File.WriteAllText(options.HostStopPath, "stop");
                    AppendLog(options.LogPath, "RollbackCompleted", "The restore script verified exact original DNS restoration.");
                    return 0;
                }

                if (!armed && (!parentAlive || DateTimeOffset.UtcNow >= options.DeadlineUtc))
                {
                    AppendLog(options.LogPath, "WatchdogStoppedBeforeArming", "No DNS change window was armed; no restore was necessary.");
                    return 0;
                }
                await Task.Delay(TimeSpan.FromSeconds(2)).ConfigureAwait(false);
            }
        }
        catch (Exception exception) when (exception is IOException or InvalidOperationException or UnauthorizedAccessException)
        {
            AppendLog(options.LogPath, "WatchdogFailed", exception.GetType().Name + ": " + exception.Message);
            Console.Error.WriteLine(exception.Message);
            return 1;
        }
    }

    private static async Task<bool> TestConnectivityAsync()
    {
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(4));
        try
        {
            var addresses = await System.Net.Dns.GetHostAddressesAsync("example.com", timeout.Token).ConfigureAwait(false);
            return addresses.Length > 0;
        }
        catch (Exception exception) when (exception is System.Net.Sockets.SocketException or OperationCanceledException) { return false; }
    }

    private static async Task<bool> RunRestoreAsync(WatchdogOptions options, DnsWatchdogTrigger trigger)
    {
        var start = new ProcessStartInfo
        {
            FileName = "powershell.exe",
            UseShellExecute = false,
            CreateNoWindow = true,
            RedirectStandardOutput = true,
            RedirectStandardError = true
        };
        foreach (var argument in new[]
        {
            "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", options.RestoreScriptPath,
            "-BackupPath", options.BackupPath, "-ApprovedRollbackFromRehearsal", "-RollbackReason", trigger.ToString()
        }) start.ArgumentList.Add(argument);
        using var process = Process.Start(start) ?? throw new InvalidOperationException("The independent restore process could not be started.");
        var outputTask = process.StandardOutput.ReadToEndAsync();
        var errorTask = process.StandardError.ReadToEndAsync();
        await process.WaitForExitAsync().ConfigureAwait(false);
        var output = await outputTask.ConfigureAwait(false);
        var error = await errorTask.ConfigureAwait(false);
        AppendLog(options.LogPath, "RestoreProcessResult", $"ExitCode={process.ExitCode}; Output={Redact(output)}; Error={Redact(error)}");
        return process.ExitCode == 0;
    }

    private static int? ReadHostProcessId(string readyPath)
    {
        try
        {
            using var document = JsonDocument.Parse(File.ReadAllText(readyPath));
            return document.RootElement.GetProperty("processId").GetInt32();
        }
        catch (Exception exception) when (exception is IOException or JsonException or KeyNotFoundException or InvalidOperationException) { return null; }
    }

    private static bool IsProcessAlive(int processId)
    {
        try { return !Process.GetProcessById(processId).HasExited; }
        catch (ArgumentException) { return false; }
    }

    private static string Redact(string value) => string.IsNullOrWhiteSpace(value) ? "[none]" : value.Replace(Environment.NewLine, " ", StringComparison.Ordinal).Trim();

    private static void WriteJsonAtomically(string path, object value)
    {
        Directory.CreateDirectory(Path.GetDirectoryName(path) ?? throw new InvalidOperationException("A state directory is required."));
        var temporary = path + ".tmp";
        File.WriteAllText(temporary, JsonSerializer.Serialize(value));
        File.Move(temporary, path, true);
    }

    private static void AppendLog(string path, string eventName, string status)
    {
        Directory.CreateDirectory(Path.GetDirectoryName(path) ?? throw new InvalidOperationException("A log directory is required."));
        File.AppendAllText(path, JsonSerializer.Serialize(new { timestampUtc = DateTimeOffset.UtcNow, eventName, status }) + Environment.NewLine);
    }
}

internal sealed record WatchdogOptions(
    string BackupPath,
    string HeartbeatPath,
    string HostReadyPath,
    string ArmedPath,
    string RollbackRequestPath,
    string RestoredPath,
    string HostStopPath,
    string CancelPath,
    string RestoreScriptPath,
    string LogPath,
    int OrchestratorProcessId,
    DateTimeOffset DeadlineUtc)
{
    public static WatchdogOptions Parse(string[] args)
    {
        var values = WatchdogCommandLine.Parse(args);
        return new WatchdogOptions(
            values.RequirePath("backup"), values.RequirePath("heartbeat"), values.RequirePath("host-ready"),
            values.RequirePath("armed"), values.RequirePath("rollback-request"), values.RequirePath("restored"),
            values.RequirePath("host-stop"), values.RequirePath("cancel"), values.RequirePath("restore-script"), values.RequirePath("log"),
            values.RequireInt32("orchestrator-pid"), values.RequireDateTimeOffset("deadline-utc"));
    }
}

internal sealed class WatchdogCommandLine
{
    private readonly Dictionary<string, string> _values;
    private WatchdogCommandLine(Dictionary<string, string> values) => _values = values;
    public static WatchdogCommandLine Parse(string[] args)
    {
        var values = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        for (var index = 0; index < args.Length; index += 2)
        {
            if (index + 1 >= args.Length || !args[index].StartsWith("--", StringComparison.Ordinal)) throw new ArgumentException("Every watchdog argument requires a --name value pair.");
            values[args[index][2..]] = args[index + 1];
        }
        return new WatchdogCommandLine(values);
    }
    public string RequirePath(string key) => Path.GetFullPath(Require(key));
    public int RequireInt32(string key) => int.Parse(Require(key), System.Globalization.CultureInfo.InvariantCulture);
    public DateTimeOffset RequireDateTimeOffset(string key) => DateTimeOffset.Parse(Require(key), System.Globalization.CultureInfo.InvariantCulture, System.Globalization.DateTimeStyles.RoundtripKind);
    private string Require(string key) => _values.TryGetValue(key, out var value) && !string.IsNullOrWhiteSpace(value) ? value : throw new ArgumentException($"Watchdog argument --{key} is required.");
}
