using System.Net;
using System.Text.Json;
using QuietShield.Core.Dns;
using QuietShield.Windows.Dns;

namespace QuietShield.DnsHost;

public static class Program
{
    public static async Task<int> Main(string[] args)
    {
        if (args.Contains("--probe", StringComparer.OrdinalIgnoreCase))
            return await DnsProbeCommand.RunAsync(args).ConfigureAwait(false);

        DnsHostOptions options;
        try { options = DnsHostOptions.Parse(args); }
        catch (Exception exception) when (exception is ArgumentException or FormatException)
        {
            Console.Error.WriteLine(exception.Message);
            return 2;
        }

        try
        {
            var validation = DnsRehearsalBackupSerializer.DeserializeAndValidate(await File.ReadAllTextAsync(options.BackupPath).ConfigureAwait(false));
            if (!validation.Succeeded || validation.Document is null) throw new InvalidDataException(validation.Status);
            var upstreams = DnsRehearsalUpstreamSelector.SelectDistinctForwardingAddresses(validation.Document)
                .Select((address, index) => new DnsEndpointIdentity(address, 53, $"Original adapter DNS {index + 1}"))
                .ToArray();
            if (upstreams.Length == 0) throw new InvalidDataException("The validated rehearsal backup contains no safe original upstream DNS server.");

            var upstream = new SafeDnsUpstreamResolver(
                new SocketDnsUpstreamTransport(),
                new DnsUpstreamOptions(upstreams, null, TimeSpan.FromSeconds(2), 1, DnsUpstreamFailurePolicy.FailClosed));
            var policy = new DnsRehearsalPolicyEvaluator();
            var policySnapshot = DnsRehearsalPolicyEvaluator.GetSnapshot();
            if (!policySnapshot.Loaded) throw new InvalidDataException(policySnapshot.Status);
            AppendLog(options.LogPath, "PolicySnapshotLoaded", $"Embedded test block loaded and normalized as {policySnapshot.NormalizedBlockedTestDomain}; decision={policySnapshot.TestDecision}.");
            await using var ipv4 = CreateRuntime(IPAddress.Loopback, policy, upstream);
            await using var ipv6 = options.EnableIpv6 ? CreateRuntime(IPAddress.IPv6Loopback, policy, upstream) : null;
            using var shutdown = new CancellationTokenSource(TimeSpan.FromSeconds(options.MaximumRuntimeSeconds));
            Console.CancelKeyPress += (_, eventArgs) => { eventArgs.Cancel = true; shutdown.Cancel(); };

            try
            {
                await ipv4.StartAsync(shutdown.Token).ConfigureAwait(false);
                if (ipv6 is not null) await ipv6.StartAsync(shutdown.Token).ConfigureAwait(false);
                var endpoint = new IPEndPoint(IPAddress.Loopback, 53);
                var udpSelfTest = await DnsRawProbeClient.ProbeAsync(endpoint, DnsRehearsalPolicyEvaluator.BlockedTestDomain, DnsRawProbeProtocol.Udp, TimeSpan.FromSeconds(5), shutdown.Token).ConfigureAwait(false);
                var tcpSelfTest = await DnsRawProbeClient.ProbeAsync(endpoint, DnsRehearsalPolicyEvaluator.BlockedTestDomain, DnsRawProbeProtocol.Tcp, TimeSpan.FromSeconds(5), shutdown.Token).ConfigureAwait(false);
                EnsureBlockedSelfTest(udpSelfTest);
                EnsureBlockedSelfTest(tcpSelfTest);
                AppendLog(options.LogPath, "RawBlockedSelfTestPassed", $"UDP and TCP returned RCODE 3 with matching transactions for {policySnapshot.NormalizedBlockedTestDomain}.");
                WriteJsonAtomically(options.ReadyPath, new
                {
                    schemaVersion = 1,
                    productMarker = "QuietShield",
                    purpose = "DnsRehearsalHostReady",
                    processId = Environment.ProcessId,
                    ipv4Port = ipv4.GetStatus().BoundPort,
                    ipv6Port = ipv6?.GetStatus().BoundPort,
                    policySnapshotLoaded = policySnapshot.Loaded,
                    normalizedBlockedTestDomain = policySnapshot.NormalizedBlockedTestDomain,
                    udpBlockedRcode = (int)udpSelfTest.Validation.ResponseCode,
                    tcpBlockedRcode = (int)tcpSelfTest.Validation.ResponseCode,
                    startedAtUtc = DateTimeOffset.UtcNow
                });
                AppendLog(options.LogPath, "HostReady", "Loopback UDP/TCP DNS host is ready; domain logging is disabled.");

                while (!shutdown.IsCancellationRequested && !File.Exists(options.StopPath))
                {
                    WriteJsonAtomically(options.HeartbeatPath, new
                    {
                        schemaVersion = 1,
                        productMarker = "QuietShield",
                        purpose = "DnsRehearsalHostHeartbeat",
                        processId = Environment.ProcessId,
                        timestampUtc = DateTimeOffset.UtcNow
                    });
                    await Task.Delay(TimeSpan.FromSeconds(2), shutdown.Token).ConfigureAwait(false);
                }
            }
            catch (OperationCanceledException) when (shutdown.IsCancellationRequested) { }
            finally
            {
                await ipv4.StopAsync(CancellationToken.None).ConfigureAwait(false);
                if (ipv6 is not null) await ipv6.StopAsync(CancellationToken.None).ConfigureAwait(false);
                AppendLog(options.LogPath, "HostStopped", "The temporary DNS host released all loopback sockets.");
            }
            return 0;
        }
        catch (Exception exception) when (exception is IOException or InvalidOperationException or System.Net.Sockets.SocketException)
        {
            AppendLog(options.LogPath, "HostFailed", exception.GetType().Name + ": " + exception.Message);
            Console.Error.WriteLine(exception.Message);
            return 1;
        }
    }

    private static LocalDnsRuntime CreateRuntime(IPAddress address, IDnsRuntimePolicyEvaluator policy, IDnsRawUpstreamResolver upstream) => new(
        LocalDnsRuntimeOptions.SafeDiagnosticDefaults with
        {
            ListenAddress = address,
            ListenPort = 53,
            MaximumConcurrentRequests = 128,
            QueryTimeout = TimeSpan.FromSeconds(4),
            BindingMode = LocalDnsBindingMode.ApprovedTemporaryPort53Rehearsal
        },
        policy,
        upstream);

    private static void EnsureBlockedSelfTest(DnsRawProbeResult result)
    {
        if (!result.Validation.Succeeded ||
            !result.Validation.IsResponse ||
            result.Validation.ExpectedTransactionId != result.Validation.ResponseTransactionId ||
            result.Validation.ResponseCode != DnsResponseCode.NameError ||
            !string.Equals(result.Validation.NormalizedQuestionName, DnsRehearsalPolicyEvaluator.BlockedTestDomain, StringComparison.Ordinal))
            throw new InvalidDataException($"The {result.Protocol} raw blocked-domain self-test did not return a valid matching NXDOMAIN response.");
    }

    private static void WriteJsonAtomically(string path, object value)
    {
        var directory = Path.GetDirectoryName(path) ?? throw new InvalidOperationException("A state directory is required.");
        Directory.CreateDirectory(directory);
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

internal sealed record DnsHostOptions(
    string BackupPath,
    string HeartbeatPath,
    string ReadyPath,
    string StopPath,
    string LogPath,
    bool EnableIpv6,
    int MaximumRuntimeSeconds)
{
    public static DnsHostOptions Parse(string[] args)
    {
        var values = CommandLineValues.Parse(args);
        var maximum = values.GetInt32("maximum-runtime-seconds", 300);
        if (maximum is < 1 or > 360) throw new ArgumentOutOfRangeException(nameof(args), "Host maximum runtime must be between 1 and 360 seconds.");
        return new DnsHostOptions(
            values.RequirePath("backup"),
            values.RequirePath("heartbeat"),
            values.RequirePath("ready"),
            values.RequirePath("stop"),
            values.RequirePath("log"),
            values.HasFlag("enable-ipv6"),
            maximum);
    }
}

internal sealed class CommandLineValues
{
    private readonly Dictionary<string, string?> _values;
    private CommandLineValues(Dictionary<string, string?> values) => _values = values;

    public static CommandLineValues Parse(string[] args)
    {
        var values = new Dictionary<string, string?>(StringComparer.OrdinalIgnoreCase);
        for (var index = 0; index < args.Length; index++)
        {
            if (!args[index].StartsWith("--", StringComparison.Ordinal)) throw new ArgumentException("Every host argument must use a --name form.");
            var key = args[index][2..];
            if (key.Equals("enable-ipv6", StringComparison.OrdinalIgnoreCase) || key.Equals("probe", StringComparison.OrdinalIgnoreCase)) { values[key] = null; continue; }
            if (++index >= args.Length) throw new ArgumentException($"Host argument --{key} requires a value.");
            values[key] = args[index];
        }
        return new CommandLineValues(values);
    }

    public bool HasFlag(string key) => _values.ContainsKey(key);
    public int GetInt32(string key, int defaultValue) => _values.TryGetValue(key, out var value) ? int.Parse(value!, System.Globalization.CultureInfo.InvariantCulture) : defaultValue;
    public string Require(string key) => _values.TryGetValue(key, out var value) && !string.IsNullOrWhiteSpace(value) ? value : throw new ArgumentException($"Host argument --{key} is required.");
    public string RequirePath(string key)
    {
        return Path.GetFullPath(Require(key));
    }
}
