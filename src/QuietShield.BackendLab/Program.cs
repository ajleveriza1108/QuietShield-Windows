// QuietShield Backend Pack 1-4 R1
using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Text.Json;
using QuietShield.Core.Backends;
using QuietShield.Windows.Backends;

namespace QuietShield.BackendLab;

internal static class Program
{
    private static readonly JsonSerializerOptions JsonOptions = new() { WriteIndented = true };
    private static async Task<int> Main(string[] args)
    {
        var seconds = ReadIntArgument(args, "--seconds", 120);
        if (seconds is < 10 or > 3600)
        {
            Console.Error.WriteLine("--seconds must be between 10 and 3600.");
            return 2;
        }

        var output = ReadStringArgument(
            args,
            "--output",
            @"D:\QuietShield-Backend-Work\BACKEND-STRESS-RESULT.json");

        Directory.CreateDirectory(Path.GetDirectoryName(output)!);

        var health = new BackendHealthSupervisor(
            TimeSpan.FromMinutes(2),
            failureThreshold: 3,
            baseRecoveryDelay: TimeSpan.FromSeconds(1));

        var telemetrySource = new WindowsNetworkTelemetrySource();
        var telemetryWindow = new NetworkTelemetryAccumulator(240);
        var readiness = WindowsDnsActivationReadinessProbe.Probe();

        var dnsPolicy = new DnsPolicyEngine(new[]
        {
            new DnsPolicyRule(
                "blocked.quietshield.test",
                DnsPolicyAction.Block,
                IncludeSubdomains: true,
                Priority: 100),
            new DnsPolicyRule(
                "*.tracker.quietshield.test",
                DnsPolicyAction.Block,
                IncludeSubdomains: true,
                Priority: 100)
        });

        await using var proxy = new DnsProxyServer(
            dnsPolicy,
            new DnsProxyConfiguration(
                IPAddress.Parse("1.1.1.1"),
                ListenPort: 0,
                QueryTimeout: TimeSpan.FromSeconds(2)));

        var proxyPort = proxy.Start();
        var started = DateTimeOffset.UtcNow;
        var deadline = started.AddSeconds(seconds);
        var process = Process.GetCurrentProcess();
        var samples = 0;
        var dnsBlockProofFailures = 0;
        var telemetryFailures = 0;
        var serviceRunningSamples = 0;
        var peakWorkingSet = 0L;
        var peakConnectionCount = 0;

        Console.WriteLine("QuietShield Backend Pack 1-4 Stress Lab");
        Console.WriteLine($"Duration: {seconds}s");
        Console.WriteLine($"DNS proxy: 127.0.0.1:{proxyPort}");
        Console.WriteLine("System DNS activation: SAFETY-GATED");
        Console.WriteLine();

        while (DateTimeOffset.UtcNow < deadline)
        {
            samples++;
            var sampleStarted = Stopwatch.GetTimestamp();

            try
            {
                var snapshot = telemetrySource.Capture();
                telemetryWindow.Add(snapshot);
                peakConnectionCount = Math.Max(
                    peakConnectionCount,
                    snapshot.Connections.Count);

                health.RecordSuccess(
                    "network-telemetry",
                    Stopwatch.GetElapsedTime(sampleStarted),
                    detail: $"connections={snapshot.Connections.Count}");
            }
            catch (Exception ex)
            {
                telemetryFailures++;
                health.RecordFailure(
                    "network-telemetry",
                    Stopwatch.GetElapsedTime(sampleStarted),
                    ex.GetType().Name + ": " + ex.Message);
            }

            if (await VerifyBlockedDnsQueryAsync(proxyPort))
            {
                health.RecordSuccess(
                    "dns-proxy",
                    TimeSpan.Zero,
                    detail: "NXDOMAIN block proof passed.");
            }
            else
            {
                dnsBlockProofFailures++;
                health.RecordFailure(
                    "dns-proxy",
                    TimeSpan.Zero,
                    "Expected NXDOMAIN block proof failed.");
            }

            var serviceRunning = IsQuietShieldServiceRunning();
            if (serviceRunning)
            {
                serviceRunningSamples++;
            }

            var plan = ProtectionAutomationEngine.Evaluate(new(
                BackendProtectionLevel.High,
                ScheduleAllowsProtection: true,
                ServiceAvailable: serviceRunning,
                DnsProxyHealthy: dnsBlockProofFailures == 0,
                DnsSystemActivationReady: readiness.SystemDnsActivationAllowed,
                IsMetered: false,
                BatterySaverActive: false,
                AggressiveWatchRequested: true,
                NetworkTelemetryAvailable: telemetryFailures == 0));

            if (health.ShouldAttemptRecovery())
            {
                health.MarkRecoveryAttempt();
            }

            process.Refresh();
            peakWorkingSet = Math.Max(peakWorkingSet, process.WorkingSet64);

            if (samples % 5 == 0)
            {
                var status = health.Snapshot();
                Console.WriteLine(
                    $"[{DateTime.Now:T}] health={status.State} " +
                    $"connections={peakConnectionCount} " +
                    $"dnsBlocked={proxy.GetMetrics().BlockedQueries} " +
                    $"service={(serviceRunning ? "Running" : "Not running")} " +
                    $"programLock={(plan.ProgramConnectionLockEnabled ? "Ready" : "Unavailable")}");
            }

            await Task.Delay(TimeSpan.FromSeconds(2));
        }

        var finalHealth = health.Snapshot();
        var telemetrySummary = telemetryWindow.Snapshot();
        var dnsMetrics = proxy.GetMetrics();
        await proxy.StopAsync();

        var result = new
        {
            schemaVersion = 1,
            purpose = "QuietShieldBackendPack1To4Stress",
            startedAtUtc = started,
            completedAtUtc = DateTimeOffset.UtcNow,
            durationSeconds = seconds,
            samples,
            backend1Stabilization = new
            {
                health = finalHealth,
                recoveryModel = "bounded exponential backoff"
            },
            backend2Dns = new
            {
                proxyPort,
                dnsMetrics,
                blockProofFailures = dnsBlockProofFailures,
                readiness,
                systemDnsActivationPerformed = false
            },
            backend3Automation = new
            {
                plannerOperational = true,
                systemMutationPerformedByPlanner = false
            },
            backend4Telemetry = new
            {
                telemetryFailures,
                peakConnectionCount,
                telemetrySummary
            },
            liveService = new
            {
                runningSamples = serviceRunningSamples,
                totalSamples = samples
            },
            process = new
            {
                peakWorkingSetMb = Math.Round(peakWorkingSet / 1024d / 1024d, 1)
            },
            overallPassed =
                dnsBlockProofFailures == 0 &&
                telemetryFailures == 0 &&
                finalHealth.State is BackendHealthState.Healthy or BackendHealthState.Degraded
        };

        await File.WriteAllTextAsync(
            output,
            JsonSerializer.Serialize(
                result,
                JsonOptions));

        Console.WriteLine();
        Console.WriteLine($"Result: {output}");
        Console.WriteLine($"Overall: {(result.overallPassed ? "PASS" : "REVIEW REQUIRED")}");
        return result.overallPassed ? 0 : 1;
    }

    private static bool IsQuietShieldServiceRunning()
    {
        try
        {
            using var process = new Process
            {
                StartInfo = new ProcessStartInfo
                {
                    FileName = "sc.exe",
                    Arguments = "query QuietShieldService",
                    UseShellExecute = false,
                    CreateNoWindow = true,
                    RedirectStandardOutput = true,
                    RedirectStandardError = true
                }
            };

            if (!process.Start())
            {
                return false;
            }

            var output = process.StandardOutput.ReadToEnd();
            process.WaitForExit(3000);
            return process.ExitCode == 0 &&
                   output.Contains("RUNNING", StringComparison.OrdinalIgnoreCase);
        }
        catch
        {
            return false;
        }
    }

    private static async Task<bool> VerifyBlockedDnsQueryAsync(int port)
    {
        try
        {
            using var client = new UdpClient(AddressFamily.InterNetwork);
            var query = BuildDnsQuery("blocked.quietshield.test");

            await client.SendAsync(
                query,
                query.Length,
                new IPEndPoint(IPAddress.Loopback, port));

            using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(2));
            var response = await client.ReceiveAsync(timeout.Token);

            return response.Buffer.Length >= 12 &&
                   (response.Buffer[3] & 0x0F) == 3;
        }
        catch
        {
            return false;
        }
    }

    private static byte[] BuildDnsQuery(string host)
    {
        var bytes = new List<byte>
        {
            0x51, 0x53,
            0x01, 0x00,
            0x00, 0x01,
            0x00, 0x00,
            0x00, 0x00,
            0x00, 0x00
        };

        foreach (var label in host.Split('.'))
        {
            var labelBytes = Encoding.ASCII.GetBytes(label);
            bytes.Add((byte)labelBytes.Length);
            bytes.AddRange(labelBytes);
        }

        bytes.Add(0);
        bytes.Add(0);
        bytes.Add(1);
        bytes.Add(0);
        bytes.Add(1);
        return bytes.ToArray();
    }

    private static int ReadIntArgument(
        string[] args,
        string name,
        int defaultValue)
    {
        var value = ReadStringArgument(args, name, string.Empty);
        return int.TryParse(value, out var parsed)
            ? parsed
            : defaultValue;
    }

    private static string ReadStringArgument(
        string[] args,
        string name,
        string defaultValue)
    {
        for (var i = 0; i < args.Length - 1; i++)
        {
            if (args[i].Equals(name, StringComparison.OrdinalIgnoreCase))
            {
                return args[i + 1];
            }
        }

        return defaultValue;
    }
}
