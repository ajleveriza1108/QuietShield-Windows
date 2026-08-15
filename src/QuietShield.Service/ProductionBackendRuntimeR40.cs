// QuietShield Backend Runtime Completion R4.0
#pragma warning disable CA1822
using System.Diagnostics;
using System.Globalization;
using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.Extensions.Hosting;
using QuietShield.Core.Dns;
using QuietShield.Core.FinalBackends;
using QuietShield.Core.IntegrationWave;
using QuietShield.Core.Protection;
using QuietShield.Core.ServiceFoundation;
using QuietShield.Windows.Dns;
using QuietShield.Windows.IntegrationWave;

namespace QuietShield.Service;

internal sealed record DnsAdapterSnapshotR40(
    string InterfaceGuid,
    int InterfaceIndex,
    string InterfaceAlias,
    bool Automatic,
    IReadOnlyList<string> ServerAddresses);

internal sealed record DnsShieldStateR40(
    int SchemaVersion,
    bool DesiredEnabled,
    bool SystemActive,
    DnsAdapterSnapshotR40? Original,
    DateTimeOffset UpdatedAtUtc,
    string Detail);

internal sealed record ProfileFirewallRuleR40(
    string RuleName,
    string StableApplicationIdentity,
    string ExecutablePath);

internal sealed record ProfileFirewallStateR40(
    int SchemaVersion,
    string Mode,
    IReadOnlyList<ProfileFirewallRuleR40> Rules,
    DateTimeOffset UpdatedAtUtc);

internal sealed record ProtectionStatisticsFileR40(
    int SchemaVersion,
    string DateLocal,
    long AdsBlocked,
    long TrackersBlocked,
    long ThreatsBlocked,
    long TotalBlocked,
    DateTimeOffset UpdatedAtUtc);

internal sealed class ProtectionStatisticsStoreR40
{
    private readonly object _sync = new();
    private readonly string _path;

    public ProtectionStatisticsStoreR40(string stateRoot)
    {
        _path = Path.Combine(stateRoot, "telemetry", "blocking-stats-today.json");
    }

    public ProtectionStatisticsSnapshotR40 Snapshot()
    {
        lock (_sync)
        {
            var state = LoadToday();
            return new(
                state.DateLocal,
                state.AdsBlocked,
                state.TrackersBlocked,
                state.ThreatsBlocked,
                state.TotalBlocked,
                state.UpdatedAtUtc,
                "Verified local QuietShield block events.");
        }
    }

    public void Record(DnsCategory? category)
    {
        lock (_sync)
        {
            var state = LoadToday();
            var ads = state.AdsBlocked;
            var trackers = state.TrackersBlocked;
            var threats = state.ThreatsBlocked;

            switch (category)
            {
                case DnsCategory.Ads:
                    ads++;
                    break;
                case DnsCategory.Trackers:
                    trackers++;
                    break;
                case DnsCategory.Malware:
                case DnsCategory.Phishing:
                case DnsCategory.Scam:
                case DnsCategory.Cryptomining:
                    threats++;
                    break;
            }

            Write(new(
                1,
                DateTime.Now.ToString("yyyy-MM-dd", CultureInfo.InvariantCulture),
                ads,
                trackers,
                threats,
                checked(ads + trackers + threats),
                DateTimeOffset.UtcNow));
        }
    }

    private ProtectionStatisticsFileR40 LoadToday()
    {
        var today = DateTime.Now.ToString("yyyy-MM-dd", CultureInfo.InvariantCulture);

        try
        {
            if (File.Exists(_path))
            {
                var state = JsonSerializer.Deserialize<ProtectionStatisticsFileR40>(
                    File.ReadAllText(_path),
                    ServiceMessageSerializer.Options);

                if (state is not null &&
                    state.SchemaVersion == 1 &&
                    string.Equals(state.DateLocal, today, StringComparison.Ordinal))
                {
                    return state;
                }
            }
        }
        catch (Exception exception) when (
            exception is IOException or UnauthorizedAccessException or JsonException)
        {
        }

        return new(
            1,
            today,
            0,
            0,
            0,
            0,
            DateTimeOffset.UtcNow);
    }

    private void Write(ProtectionStatisticsFileR40 state)
    {
        var directory =
            Path.GetDirectoryName(_path)
            ?? throw new InvalidOperationException("Telemetry directory is unavailable.");

        Directory.CreateDirectory(directory);

        var temporary =
            _path + "." + Guid.NewGuid().ToString("N") + ".tmp";

        var bytes =
            JsonSerializer.SerializeToUtf8Bytes(
                state,
                ServiceMessageSerializer.Options);

        try
        {
            using (var stream = new FileStream(
                temporary,
                FileMode.CreateNew,
                FileAccess.Write,
                FileShare.None,
                4096,
                FileOptions.WriteThrough))
            {
                stream.Write(bytes);
                stream.Flush(true);
            }

            File.Move(temporary, _path, true);
        }
        finally
        {
            if (File.Exists(temporary))
                File.Delete(temporary);
        }
    }
}

internal sealed class ProductionDnsPolicyR40 : IDnsRuntimePolicyEvaluator
{
    private static readonly string[] AdSuffixes =
    [
        "doubleclick.net", "googleadservices.com", "googlesyndication.com",
        "amazon-adsystem.com", "adnxs.com", "adsrvr.org", "pubmatic.com",
        "rubiconproject.com", "openx.net", "criteo.com", "criteo.net",
        "taboola.com", "outbrain.com", "media.net", "casalemedia.com",
        "advertising.com", "adform.net", "smartadserver.com", "yieldmo.com",
        "adroll.com", "bidswitch.net", "contextweb.com", "lijit.com",
        "sharethrough.com", "smaato.net"
    ];

    private static readonly string[] TrackerSuffixes =
    [
        "google-analytics.com", "analytics.google.com", "googletagmanager.com",
        "hotjar.com", "clarity.ms", "scorecardresearch.com", "quantserve.com",
        "segment.com", "segment.io", "mixpanel.com", "amplitude.com",
        "connect.facebook.net", "bat.bing.com", "newrelic.com", "nr-data.net",
        "branch.io", "app-measurement.com", "adjust.com", "appsflyer.com"
    ];

    private readonly string _allowPath;
    private readonly string _blockPath;

    public ProductionDnsPolicyR40(string stateRoot)
    {
        var root = Path.Combine(stateRoot, "dns");
        _allowPath = Path.Combine(root, "allowlist.txt");
        _blockPath = Path.Combine(root, "blocklist.txt");
    }

    public Task<DnsPolicyResult> EvaluateAsync(
        string normalizedDomain,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();

        var domain = normalizedDomain.Trim().TrimEnd('.').ToLowerInvariant();

        if (MatchesFile(_allowPath, domain))
        {
            return Task.FromResult(Result(
                DnsDecision.Allow, null, domain,
                "QuietShield custom allowlist",
                "Custom allowlist takes precedence."));
        }

        if (string.Equals(domain, "quietshield-blocked.test", StringComparison.Ordinal))
        {
            return Task.FromResult(Result(
                DnsDecision.Block, DnsCategory.Custom, domain,
                "QuietShield deterministic self-test",
                "Deterministic QuietShield blocked-domain self-test."));
        }

        if (MatchesFile(_blockPath, domain))
        {
            return Task.FromResult(Result(
                DnsDecision.Block, DnsCategory.Custom, domain,
                "QuietShield custom blocklist",
                "Matched the local custom blocklist."));
        }

        var category = Classify(domain);
        if (category.HasValue)
        {
            return Task.FromResult(Result(
                DnsDecision.Block, category, domain,
                category == DnsCategory.Ads
                    ? "QuietShield built-in ad protection"
                    : "QuietShield built-in tracker protection",
                category == DnsCategory.Ads
                    ? "Matched a known advertising host."
                    : "Matched a known tracking host."));
        }

        return Task.FromResult(Result(
            DnsDecision.Allow, null, null,
            "QuietShield default allow",
            "No blocking rule matched."));
    }

    public DnsCategory? Classify(string domain)
    {
        if (MatchesSuffixes(domain, AdSuffixes))
            return DnsCategory.Ads;
        if (MatchesSuffixes(domain, TrackerSuffixes))
            return DnsCategory.Trackers;
        return null;
    }

    private static bool MatchesSuffixes(string domain, IReadOnlyList<string> suffixes)
    {
        foreach (var suffix in suffixes)
        {
            if (string.Equals(domain, suffix, StringComparison.OrdinalIgnoreCase) ||
                domain.EndsWith("." + suffix, StringComparison.OrdinalIgnoreCase))
                return true;
        }
        return false;
    }

    private static bool MatchesFile(string path, string domain)
    {
        try
        {
            if (!File.Exists(path))
                return false;

            foreach (var raw in File.ReadLines(path))
            {
                var value = raw.Trim().TrimEnd('.').ToLowerInvariant();
                if (value.Length == 0 || value.StartsWith('#'))
                    continue;
                if (value.StartsWith("*.", StringComparison.Ordinal))
                    value = value[2..];

                if (string.Equals(domain, value, StringComparison.Ordinal) ||
                    domain.EndsWith("." + value, StringComparison.Ordinal))
                    return true;
            }
        }
        catch (Exception exception) when (
            exception is IOException or UnauthorizedAccessException)
        {
        }
        return false;
    }

    private static DnsPolicyResult Result(
        DnsDecision decision,
        DnsCategory? category,
        string? matchedRule,
        string source,
        string reason) =>
        new(
            decision, category, matchedRule, [source], reason,
            DateTimeOffset.UtcNow, matchedRule);
}

internal sealed class ProductionCountingDnsPolicyR40 : IDnsRuntimePolicyEvaluator
{
    private readonly ProductionDnsPolicyR40 _inner;
    private readonly ProtectionStatisticsStoreR40 _statistics;

    public ProductionCountingDnsPolicyR40(
        ProductionDnsPolicyR40 inner,
        ProtectionStatisticsStoreR40 statistics)
    {
        _inner = inner;
        _statistics = statistics;
    }

    public async Task<DnsPolicyResult> EvaluateAsync(
        string normalizedDomain,
        CancellationToken cancellationToken)
    {
        var result =
            await _inner.EvaluateAsync(
                normalizedDomain,
                cancellationToken).ConfigureAwait(false);

        if (result.Decision == DnsDecision.Block)
            _statistics.Record(result.Category);

        return result;
    }
}

internal sealed class ProductionBackendRuntimeR40 : IHostedService, IAsyncDisposable
{
    private static readonly TimeSpan DnsProbeTimeout = TimeSpan.FromSeconds(5);
    private readonly SemaphoreSlim _gate = new(1, 1);
    private readonly PersistentServiceRuntime _persistentRuntime;
    private readonly AtomicJsonStateStore<DnsShieldStateR40> _dnsStateStore = new(1);
    private readonly string _dnsStatePath;
    private readonly string _profileStatePath;
    private readonly ProductionDnsPolicyR40 _dnsPolicy;
    private readonly ProtectionStatisticsStoreR40 _statistics;
    private readonly ProductionCountingDnsPolicyR40 _countingDnsPolicy;
    private LocalDnsRuntime? _dnsRuntime;
    private DnsShieldStateR40 _dnsState;
    private ProfileFirewallStateR40 _profileState;

    public ProductionBackendRuntimeR40(
        DiagnosticServiceOptions options,
        PersistentServiceRuntime persistentRuntime)
    {
        _persistentRuntime = persistentRuntime;

        var root = Path.Combine(options.StateRoot, "backend-r40");
        _dnsStatePath = Path.Combine(root, "dns-state.json");
        _profileStatePath = Path.Combine(root, "profile-firewall-state.json");

        _dnsPolicy = new ProductionDnsPolicyR40(options.StateRoot);
        _statistics = new ProtectionStatisticsStoreR40(options.StateRoot);
        _countingDnsPolicy = new ProductionCountingDnsPolicyR40(_dnsPolicy, _statistics);

        _dnsState = new(
            1, false, false, null, DateTimeOffset.UtcNow,
            "DNS Shield has not been activated.");

        _profileState = new(
            1, "WiFi", Array.Empty<ProfileFirewallRuleR40>(),
            DateTimeOffset.UtcNow);
    }

    public async Task StartAsync(CancellationToken cancellationToken)
    {
        Directory.CreateDirectory(Path.GetDirectoryName(_dnsStatePath)!);

        _profileState = await LoadProfileStateAsync(cancellationToken).ConfigureAwait(false);
        _dnsState = await LoadDnsStateAsync(cancellationToken).ConfigureAwait(false);

        if (_dnsState.SystemActive)
            await RecoverInterruptedDnsStateAsync(cancellationToken).ConfigureAwait(false);

        if (_dnsState.DesiredEnabled && !_dnsState.SystemActive)
        {
            try
            {
                await ActivateDnsShieldCoreAsync(
                    explicitUserApproval: true,
                    recoveryMode: true,
                    cancellationToken).ConfigureAwait(false);
            }
            catch
            {
            }
        }
    }

    public async Task StopAsync(CancellationToken cancellationToken)
    {
        await _gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            if (_dnsState.SystemActive && _dnsState.Original is not null)
            {
                await RestoreOriginalDnsAsync(
                    _dnsState.Original,
                    cancellationToken).ConfigureAwait(false);

                _dnsState = _dnsState with
                {
                    SystemActive = false,
                    UpdatedAtUtc = DateTimeOffset.UtcNow,
                    Detail = "Original DNS restored while QuietShield service stopped."
                };

                await SaveDnsStateAsync(_dnsState, cancellationToken).ConfigureAwait(false);
            }

            await StopDnsRuntimeAsync(cancellationToken).ConfigureAwait(false);
        }
        finally
        {
            _gate.Release();
        }
    }

    public BackendStatusSnapshotR40 GetStatus()
    {
        var runtimeStatus = _dnsRuntime?.GetStatus();

        return new(
            DnsRuntimeRunning:
                runtimeStatus?.State == LocalDnsRuntimeState.Running,
            DnsSystemActive: _dnsState.SystemActive,
            DnsDesiredEnabled: _dnsState.DesiredEnabled,
            DataSavingEnforcementActive:
                string.Equals(_profileState.Mode, "DataSaving", StringComparison.OrdinalIgnoreCase),
            DataSavingRuleCount: _profileState.Rules.Count,
            ProgramConnectionLockAvailable:
                _persistentRuntime.GetStatus().PersistentEnforcementAvailable,
            PrivateBrowserFilteringAvailable: true,
            FileSafetyAvailable: true,
            ParentChildBackendAvailable: true,
            ScheduleBackendAvailable: true,
            TelemetryBackendAvailable: true,
            LicensingBackendAvailable: true,
            UpdaterBackendAvailable: true,
            TrayBackendAvailable: true,
            OverallStatus:
                _dnsState.SystemActive
                    ? "Protection backends are active."
                    : "Backend runtime is available; DNS Shield is not system-active.",
            Detail: _dnsState.Detail);
    }

    public ProtectionStatisticsSnapshotR40 GetStatistics() =>
        _statistics.Snapshot();

    public async Task<BackendSelfTestResultR40> RunSelfTestAsync(
        CancellationToken cancellationToken)
    {
        var checks = new List<BackendSelfTestCheckR40>();

        await AddCheckAsync(checks, "DNS policy: ad", async () =>
        {
            var result = await _dnsPolicy.EvaluateAsync(
                "doubleclick.net", cancellationToken).ConfigureAwait(false);
            return result.Decision == DnsDecision.Block &&
                   result.Category == DnsCategory.Ads;
        }).ConfigureAwait(false);

        await AddCheckAsync(checks, "DNS policy: tracker", async () =>
        {
            var result = await _dnsPolicy.EvaluateAsync(
                "google-analytics.com", cancellationToken).ConfigureAwait(false);
            return result.Decision == DnsDecision.Block &&
                   result.Category == DnsCategory.Trackers;
        }).ConfigureAwait(false);

        await AddCheckAsync(checks, "DNS policy: normal", async () =>
        {
            var result = await _dnsPolicy.EvaluateAsync(
                "example.com", cancellationToken).ConfigureAwait(false);
            return result.Decision == DnsDecision.Allow;
        }).ConfigureAwait(false);
                await AddCheckAsync(checks, "DNS live runtime UDP/TCP", async () =>
        {
            // R4.2.2 live DNS listener self-test: policy-only checks are not enough
            // when Windows is actively routed to the loopback DNS runtime.
            // R4.2.3 bounded live DNS self-test budget: run UDP/TCP health probes
            // concurrently with independent 3-second socket deadlines. Never let
            // the IPC request cancellation token turn a listener-health result into
            // an unhandled command-level OperationCanceledException.
            if (!_dnsState.SystemActive)
                return true;

            var endpoint = new IPEndPoint(IPAddress.Loopback, 53);
            var protocols = new[]
            {
                DnsRawProbeProtocol.Udp,
                DnsRawProbeProtocol.Tcp
            };

            var probeTasks = protocols.Select(async protocol =>
            {
                try
                {
                    var result = await DnsRawProbeClient.ProbeAsync(
                        endpoint,
                        "quietshield-blocked.test",
                        protocol,
                        TimeSpan.FromSeconds(3),
                        CancellationToken.None).ConfigureAwait(false);

                    var passed =
                        result.Validation.Succeeded &&
                        result.Validation.IsResponse &&
                        result.Validation.ResponseCode == DnsResponseCode.NameError;

                    return (
                        Protocol: protocol,
                        Passed: passed,
                        Detail: passed
                            ? "Passed."
                            : "The DNS response failed QuietShield validation.");
                }
                catch (Exception exception)
                {
                    return (
                        Protocol: protocol,
                        Passed: false,
                        Detail: exception.GetType().Name + ": " + exception.Message);
                }
            }).ToArray();

            var results = await Task.WhenAll(probeTasks).ConfigureAwait(false);
            var failures = results.Where(static result => !result.Passed).ToArray();
            if (failures.Length > 0)
            {
                throw new InvalidOperationException(
                    string.Join(
                        "; ",
                        failures.Select(static failure =>
                            failure.Protocol + ": " + failure.Detail)));
            }

            return true;
        }).ConfigureAwait(false);

        await AddCheckAsync(checks, "Schedule engine", () =>
        {
            var now = DateTimeOffset.Now;
            var entry = new ProtectionScheduleEntry(
                "self-test", true, now.DayOfWeek,
                new TimeOnly(0, 0), new TimeOnly(23, 59),
                ProtectionProfilePreset.Balanced, 1);
            var result = ProtectionScheduleEngine.Evaluate([entry], now);
            return Task.FromResult(result.Matched);
        }).ConfigureAwait(false);

        await AddCheckAsync(checks, "Parent child policy", () =>
        {
            var key = ParentChildRuntimeCoordinator.CreateIntegrityKey();
            var coordinator = new ParentChildRuntimeCoordinator(key);
            var decision = coordinator.Evaluate(new(
                FamilyRole.Parent, DateTimeOffset.Now, "self-test", null));
            return Task.FromResult(!coordinator.HasPolicy && decision.Allowed);
        }).ConfigureAwait(false);

        await AddCheckAsync(checks, "Network telemetry sampler", () =>
        {
            var sample = WindowsNetworkUsageSampler.Capture();
            return Task.FromResult(
                sample.BytesReceived >= 0 && sample.BytesSent >= 0);
        }).ConfigureAwait(false);

        await AddCheckAsync(checks, "File safety pipeline", async () =>
        {
            var path = Path.Combine(
                Path.GetTempPath(),
                "quietshield-r40-self-test-" + Guid.NewGuid().ToString("N") + ".txt");
            try
            {
                await File.WriteAllTextAsync(
                    path, "QuietShield backend self-test", cancellationToken).ConfigureAwait(false);
                var result = await FileSafetyPipeline.InspectAsync(
                    path, runDefenderForHighRisk: false, cancellationToken).ConfigureAwait(false);
                return !string.IsNullOrWhiteSpace(result.StaticReport.Sha256);
            }
            finally
            {
                File.Delete(path);
            }
        }).ConfigureAwait(false);

        var passed = checks.All(static check => check.Passed);
        return new(
            passed, checks,
            passed
                ? "All runtime backend self-tests passed."
                : "One or more runtime backend self-tests failed.",
            DateTimeOffset.UtcNow);
    }

    public async Task<DnsShieldActivationResponseR40> SetDnsShieldAsync(
        DnsShieldActivationRequestR40 request,
        CancellationToken cancellationToken)
    {
        await _gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            if (request.Enable)
            {
                if (!request.ExplicitUserApproval)
                    return new(false, _dnsState.SystemActive, false, "Explicit user approval is required.");

                if (_dnsState.SystemActive)
                    return new(true, true, true, "DNS Shield is already active.");

                return await ActivateDnsShieldCoreAsync(
                    true, false, cancellationToken).ConfigureAwait(false);
            }

            _dnsState = _dnsState with
            {
                DesiredEnabled = false,
                UpdatedAtUtc = DateTimeOffset.UtcNow
            };

            if (_dnsState.SystemActive && _dnsState.Original is not null)
                await RestoreOriginalDnsAsync(_dnsState.Original, cancellationToken).ConfigureAwait(false);

            await StopDnsRuntimeAsync(cancellationToken).ConfigureAwait(false);

            _dnsState = _dnsState with
            {
                SystemActive = false,
                UpdatedAtUtc = DateTimeOffset.UtcNow,
                Detail = "DNS Shield is disabled and original DNS is restored."
            };

            await SaveDnsStateAsync(_dnsState, cancellationToken).ConfigureAwait(false);
            return new(true, false, true, _dnsState.Detail);
        }
        finally
        {
            _gate.Release();
        }
    }

    public async Task<OperatingModeEnforcementResponseR40> ApplyOperatingModeAsync(
        OperatingModeEnforcementRequestR40 request,
        CancellationToken cancellationToken)
    {
        await _gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            var mode = request.Mode.Trim();

            if (!string.Equals(mode, "DataSaving", StringComparison.OrdinalIgnoreCase) &&
                !string.Equals(mode, "WiFi", StringComparison.OrdinalIgnoreCase))
            {
                return new(false, _profileState.Mode, _profileState.Rules.Count,
                    "Only DataSaving and WiFi modes are supported.");
            }

            var previous = _profileState;
            var desired = new List<ProfileFirewallRuleR40>();

            if (string.Equals(mode, "DataSaving", StringComparison.OrdinalIgnoreCase))
            {
                var explicitPolicies =
                    _persistentRuntime.GetState().ProgramPolicies
                        .Where(static item => item.Enabled)
                        .ToDictionary(
                            static item => item.StableApplicationIdentity,
                            static item => item.Policy,
                            StringComparer.Ordinal);

                foreach (var target in request.Programs)
                {
                    if (target.IsWindowsSystemComponent ||
                        target.Selected ||
                        string.IsNullOrWhiteSpace(target.ExecutablePath))
                        continue;

                    if (explicitPolicies.TryGetValue(
                        target.StableApplicationIdentity, out var explicitPolicy))
                    {
                        if (explicitPolicy is
                            ProgramConnectionPolicy.AllowedOnAll or
                            ProgramConnectionPolicy.Blocked)
                            continue;
                    }

                    var fullPath = Path.GetFullPath(target.ExecutablePath);
                    if (!File.Exists(fullPath))
                        continue;

                    desired.Add(new(
                        CreateProfileRuleName(target.StableApplicationIdentity, fullPath),
                        target.StableApplicationIdentity,
                        fullPath));
                }
            }

            try
            {
                await ApplyProfileRulesAsync(desired, cancellationToken).ConfigureAwait(false);

                _profileState = new(
                    1,
                    string.Equals(mode, "DataSaving", StringComparison.OrdinalIgnoreCase)
                        ? "DataSaving"
                        : "WiFi",
                    desired,
                    DateTimeOffset.UtcNow);

                await SaveProfileStateAsync(_profileState, cancellationToken).ConfigureAwait(false);

                return new(
                    true,
                    _profileState.Mode,
                    _profileState.Rules.Count,
                    _profileState.Mode == "DataSaving"
                        ? "Data Saving enforcement is active for unselected supported user applications."
                        : "Wi-Fi mode is unrestricted; QuietShield profile rules were removed.");
            }
            catch
            {
                await ApplyProfileRulesAsync(previous.Rules, cancellationToken).ConfigureAwait(false);
                _profileState = previous;
                throw;
            }
        }
        finally
        {
            _gate.Release();
        }
    }

    public void RecordPrivateBrowserBlock(PrivateBrowserBlockEventR40 request)
    {
        var category =
            request.Category.Equals("ad", StringComparison.OrdinalIgnoreCase)
                ? DnsCategory.Ads
                : request.Category.Equals("tracker", StringComparison.OrdinalIgnoreCase)
                    ? DnsCategory.Trackers
                    : (DnsCategory?)null;

        _statistics.Record(category);
    }

    public async Task<FileSafetyScanResponseR40> ScanFileAsync(
        FileSafetyScanRequestR40 request,
        CancellationToken cancellationToken)
    {
        var result = await FileSafetyPipeline.InspectAsync(
            request.Path, request.RunDefenderForHighRisk, cancellationToken).ConfigureAwait(false);

        return new(
            true,
            result.StaticReport.Risk.ToString(),
            result.StaticReport.Sha256,
            result.Defender?.ScanStarted ?? false,
            result.Defender?.ExitCode,
            result.Summary);
    }

    public async ValueTask DisposeAsync()
    {
        await StopDnsRuntimeAsync(CancellationToken.None).ConfigureAwait(false);
        _gate.Dispose();
        GC.SuppressFinalize(this);
    }

    private async Task<DnsShieldActivationResponseR40> ActivateDnsShieldCoreAsync(
        bool explicitUserApproval,
        bool recoveryMode,
        CancellationToken cancellationToken)
    {
        if (!explicitUserApproval)
            return new(false, false, false, "Explicit user approval is required.");

        DnsAdapterSnapshotR40 original =
            recoveryMode && _dnsState.Original is not null
                ? _dnsState.Original
                : await CaptureSingleSupportedAdapterAsync(cancellationToken).ConfigureAwait(false);

        var upstreamAddresses =
            original.ServerAddresses
                .Where(static address =>
                    IPAddress.TryParse(address, out var parsed) &&
                    !IPAddress.IsLoopback(parsed))
                .Distinct(StringComparer.OrdinalIgnoreCase)
                .ToList();

        if (upstreamAddresses.Count == 0)
        {
            upstreamAddresses.Add("1.1.1.1");
            upstreamAddresses.Add("1.0.0.1");
        }

        _dnsState = new(
            1, true, false, original, DateTimeOffset.UtcNow,
            recoveryMode
                ? "Recovering DNS Shield runtime."
                : "Preparing DNS Shield activation.");

        await SaveDnsStateAsync(_dnsState, cancellationToken).ConfigureAwait(false);

        try
        {
            await StartDnsRuntimeAsync(upstreamAddresses, cancellationToken).ConfigureAwait(false);
            await VerifyLocalRuntimeAsync(cancellationToken).ConfigureAwait(false);

            // Mandatory Phase 5 process-boundary gate. No adapter mutation
            // happens until BOTH separate-process probes pass.
            await RunExternalProbeAsync("udp", cancellationToken).ConfigureAwait(false);
            await RunExternalProbeAsync("tcp", cancellationToken).ConfigureAwait(false);

            if (!recoveryMode ||
                !await AdapterUsesLoopbackAsync(
                    original.InterfaceIndex, cancellationToken).ConfigureAwait(false))
            {
                await SetAdapterDnsLoopbackAsync(
                    original.InterfaceIndex, cancellationToken).ConfigureAwait(false);
            }

            if (!await AdapterUsesLoopbackAsync(
                original.InterfaceIndex, cancellationToken).ConfigureAwait(false))
            {
                throw new InvalidOperationException(
                    "Windows did not report the approved adapter using QuietShield loopback DNS.");
            }

            await VerifyLocalRuntimeAsync(cancellationToken).ConfigureAwait(false);

            _dnsState = _dnsState with
            {
                SystemActive = true,
                UpdatedAtUtc = DateTimeOffset.UtcNow,
                Detail =
                    "DNS Shield is active. External UDP/TCP process-boundary probes passed before adapter activation."
            };

            await SaveDnsStateAsync(_dnsState, cancellationToken).ConfigureAwait(false);

            return new(true, true, true, _dnsState.Detail);
        }
        catch (Exception exception)
        {
            try
            {
                if (await AdapterUsesLoopbackAsync(
                    original.InterfaceIndex, cancellationToken).ConfigureAwait(false))
                {
                    await RestoreOriginalDnsAsync(original, cancellationToken).ConfigureAwait(false);
                }
            }
            finally
            {
                await StopDnsRuntimeAsync(cancellationToken).ConfigureAwait(false);

                _dnsState = _dnsState with
                {
                    SystemActive = false,
                    UpdatedAtUtc = DateTimeOffset.UtcNow,
                    Detail =
                        "DNS Shield activation failed safely before commit or rolled back: " +
                        exception.Message
                };

                await SaveDnsStateAsync(_dnsState, cancellationToken).ConfigureAwait(false);
            }

            return new(false, false, false, _dnsState.Detail);
        }
    }

    private async Task RecoverInterruptedDnsStateAsync(CancellationToken cancellationToken)
    {
        if (_dnsState.Original is null)
        {
            _dnsState = _dnsState with
            {
                SystemActive = false,
                DesiredEnabled = false,
                Detail = "Invalid DNS recovery state was cleared.",
                UpdatedAtUtc = DateTimeOffset.UtcNow
            };

            await SaveDnsStateAsync(_dnsState, cancellationToken).ConfigureAwait(false);
            return;
        }

        if (!await AdapterUsesLoopbackAsync(
            _dnsState.Original.InterfaceIndex, cancellationToken).ConfigureAwait(false))
        {
            _dnsState = _dnsState with
            {
                SystemActive = false,
                // R4.2.11: never carry a vanished interface index into recovery.
                // DesiredEnabled is intentionally preserved; any later reactivation
                // must still pass the unchanged external UDP + TCP activation gate.
                Original = null,
                Detail = "Adapter no longer points to QuietShield; runtime recovery was not forced.",
                UpdatedAtUtc = DateTimeOffset.UtcNow
            };

            await SaveDnsStateAsync(_dnsState, cancellationToken).ConfigureAwait(false);
        }
    }

    private async Task StartDnsRuntimeAsync(
        IReadOnlyList<string> upstreamAddresses,
        CancellationToken cancellationToken)
    {
        await StopDnsRuntimeAsync(cancellationToken).ConfigureAwait(false);

        var endpoints =
            upstreamAddresses
                .Select(static (address, index) =>
                    new DnsEndpointIdentity(
                        address,
                        53,
                        "Original DNS " + (index + 1).ToString(CultureInfo.InvariantCulture)))
                .ToArray();

        var upstream =
            new SafeDnsUpstreamResolver(
                new SocketDnsUpstreamTransport(),
                new DnsUpstreamOptions(
                    endpoints,
                    new DnsEndpointIdentity(
                        "9.9.9.9", 53, "QuietShield emergency upstream"),
                    TimeSpan.FromSeconds(3),
                    1,
                    DnsUpstreamFailurePolicy.FailOpenToExplicitEmergencyUpstream));

        var options =
            new LocalDnsRuntimeOptions(
                IPAddress.Loopback,
                53,
                DnsWireProtocol.MaximumUdpPacketSize,
                128,
                TimeSpan.FromSeconds(5),
                DnsIndeterminatePolicy.FailOpenToConfiguredUpstream,
                false)
            {
                BindingMode = LocalDnsBindingMode.ProductionLoopbackPort53
            };

        _dnsRuntime =
            new LocalDnsRuntime(options, _countingDnsPolicy, upstream);

        var port =
            await _dnsRuntime.StartAsync(cancellationToken).ConfigureAwait(false);

        if (port != 53)
            throw new InvalidOperationException(
                "QuietShield DNS runtime did not bind loopback port 53.");
    }

    private async Task StopDnsRuntimeAsync(CancellationToken cancellationToken)
    {
        if (_dnsRuntime is null)
            return;

        try
        {
            await _dnsRuntime.StopAsync(cancellationToken).ConfigureAwait(false);
        }
        finally
        {
            await _dnsRuntime.DisposeAsync().ConfigureAwait(false);
            _dnsRuntime = null;
        }
    }

    private async Task VerifyLocalRuntimeAsync(CancellationToken cancellationToken)
    {
        var endpoint = new IPEndPoint(IPAddress.Loopback, 53);

        foreach (var protocol in new[]
        {
            DnsRawProbeProtocol.Udp,
            DnsRawProbeProtocol.Tcp
        })
        {
            var blocked =
                await DnsRawProbeClient.ProbeAsync(
                    endpoint,
                    "quietshield-blocked.test",
                    protocol,
                    DnsProbeTimeout,
                    cancellationToken).ConfigureAwait(false);

            if (!blocked.Validation.Succeeded ||
                blocked.Validation.ResponseCode != DnsResponseCode.NameError)
            {
                throw new InvalidOperationException(
                    "QuietShield blocked-domain " + protocol +
                    " probe did not return NXDOMAIN.");
            }
        }

        var allowed =
            await DnsRawProbeClient.ProbeAsync(
                endpoint,
                "example.com",
                DnsRawProbeProtocol.Udp,
                DnsProbeTimeout,
                cancellationToken).ConfigureAwait(false);

        if (!allowed.Validation.Succeeded ||
            allowed.Validation.ResponseCode != DnsResponseCode.NoError)
        {
            throw new InvalidOperationException(
                "QuietShield allowed-domain upstream probe failed.");
        }
    }

    private static async Task AddCheckAsync(
        List<BackendSelfTestCheckR40> checks,
        string name,
        Func<Task<bool>> check)
    {
        try
        {
            var passed = await check().ConfigureAwait(false);
            checks.Add(new(
                name,
                passed,
                passed ? "Passed." : "Returned an unexpected result."));
        }
        catch (Exception exception)
        {
            checks.Add(new(name, false, exception.Message));
        }
    }

    private async Task RunExternalProbeAsync(
        string protocol,
        CancellationToken cancellationToken)
    {
        var probeExe =
            Path.Combine(AppContext.BaseDirectory, "QuietShield.DnsHost.exe");

        if (!File.Exists(probeExe))
            throw new FileNotFoundException(
                "The separate QuietShield DNS probe executable is missing.",
                probeExe);

        var probeOutputDirectory = Path.Combine(
            Path.GetDirectoryName(_dnsStatePath)!,
            "external-probe");
        Directory.CreateDirectory(probeOutputDirectory);

        var probeOutputPath = Path.Combine(
            probeOutputDirectory,
            "dns-probe-" + protocol + "-" +
            Guid.NewGuid().ToString("N") + ".json");

        try
        {
            using var process = new Process
            {
                StartInfo = new ProcessStartInfo
                {
                    FileName = probeExe,
                    UseShellExecute = false,
                    CreateNoWindow = true,
                    RedirectStandardOutput = true,
                    RedirectStandardError = true,
                    WorkingDirectory = AppContext.BaseDirectory
                }
            };

            process.StartInfo.ArgumentList.Add("--probe");
            process.StartInfo.ArgumentList.Add("--server");
            process.StartInfo.ArgumentList.Add("127.0.0.1");
            process.StartInfo.ArgumentList.Add("--port");
            process.StartInfo.ArgumentList.Add("53");
            process.StartInfo.ArgumentList.Add("--domain");
            process.StartInfo.ArgumentList.Add("quietshield-blocked.test");
            process.StartInfo.ArgumentList.Add("--protocol");
            process.StartInfo.ArgumentList.Add(protocol);
            process.StartInfo.ArgumentList.Add("--expected-rcode");
            process.StartInfo.ArgumentList.Add("3");
            process.StartInfo.ArgumentList.Add("--timeout-ms");
            process.StartInfo.ArgumentList.Add("5000");
            process.StartInfo.ArgumentList.Add("--output");
            process.StartInfo.ArgumentList.Add(probeOutputPath);

            if (!process.Start())
                throw new InvalidOperationException(
                    "The separate DNS process-boundary probe did not start.");

            var standardOutput = process.StandardOutput.ReadToEndAsync(cancellationToken);
            var standardError = process.StandardError.ReadToEndAsync(cancellationToken);

            await process.WaitForExitAsync(cancellationToken).ConfigureAwait(false);

            var output = await standardOutput.ConfigureAwait(false);
            var error = await standardError.ConfigureAwait(false);

            if (process.ExitCode != 0)
            {
                throw new InvalidOperationException(
                    "Separate DNS " + protocol +
                    " probe failed with exit code " +
                    process.ExitCode.ToString(CultureInfo.InvariantCulture) +
                    ". " + (string.IsNullOrWhiteSpace(error) ? output : error));
            }

            if (!File.Exists(probeOutputPath))
                throw new InvalidOperationException(
                    "The separate DNS " + protocol +
                    " probe returned success without a proof file.");

            var proofJson = await File.ReadAllTextAsync(
                probeOutputPath,
                cancellationToken).ConfigureAwait(false);
            using var proof = JsonDocument.Parse(proofJson);
            var root = proof.RootElement;

            var validProof =
                root.TryGetProperty("schemaVersion", out var schemaVersion) &&
                schemaVersion.ValueKind == JsonValueKind.Number &&
                schemaVersion.GetInt32() == 1 &&
                root.TryGetProperty("productMarker", out var productMarker) &&
                productMarker.ValueKind == JsonValueKind.String &&
                string.Equals(productMarker.GetString(), "QuietShield", StringComparison.Ordinal) &&
                root.TryGetProperty("purpose", out var purpose) &&
                purpose.ValueKind == JsonValueKind.String &&
                string.Equals(purpose.GetString(), "DnsRehearsalRawProbe", StringComparison.Ordinal) &&
                root.TryGetProperty("protocol", out var proofProtocol) &&
                proofProtocol.ValueKind == JsonValueKind.String &&
                string.Equals(proofProtocol.GetString(), protocol, StringComparison.OrdinalIgnoreCase) &&
                root.TryGetProperty("validationSucceeded", out var validationSucceeded) &&
                validationSucceeded.ValueKind == JsonValueKind.True &&
                root.TryGetProperty("isResponse", out var isResponse) &&
                isResponse.ValueKind == JsonValueKind.True &&
                root.TryGetProperty("responseCode", out var responseCode) &&
                responseCode.ValueKind == JsonValueKind.Number &&
                responseCode.GetInt32() == 3 &&
                root.TryGetProperty("passed", out var passed) &&
                passed.ValueKind == JsonValueKind.True;

            if (!validProof)
            {
                throw new InvalidOperationException(
                    "The separate DNS " + protocol +
                    " probe proof did not satisfy the QuietShield safety contract.");
            }
        }
        finally
        {
            File.Delete(probeOutputPath);
            File.Delete(probeOutputPath + ".tmp");
        }
    }

    private async Task<DnsAdapterSnapshotR40> CaptureSingleSupportedAdapterAsync(
        CancellationToken cancellationToken)
    {
        const string script = """
$ErrorActionPreference = 'Stop'
$items = @(
    Get-NetAdapter -Physical |
    Where-Object {
        $_.Status -eq 'Up' -and
        $_.HardwareInterface -eq $true -and
        $_.Virtual -eq $false -and
        (([int]$_.InterfaceType -eq 6) -or ([int]$_.InterfaceType -eq 71))
    }
)
if ($items.Count -ne 1) {
    throw ('QuietShield requires exactly one active supported physical Wi-Fi or Ethernet adapter for the initial production DNS safety gate. Found=' + $items.Count)
}
$a = $items[0]
$guid = ([Guid]$a.InterfaceGuid).ToString('D')
$reg = 'HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\' + $guid
$nameServer = $null
try { $nameServer = (Get-ItemProperty -LiteralPath $reg -Name NameServer -ErrorAction Stop).NameServer } catch {}
$automatic = [string]::IsNullOrWhiteSpace([string]$nameServer)
$servers = @(
    (Get-DnsClientServerAddress -InterfaceIndex ([int]$a.ifIndex) -AddressFamily IPv4 -ErrorAction Stop).ServerAddresses
)
[pscustomobject]@{
    interfaceGuid = $guid
    interfaceIndex = [int]$a.ifIndex
    interfaceAlias = [string]$a.Name
    automatic = [bool]$automatic
    serverAddresses = @($servers)
} | ConvertTo-Json -Depth 5 -Compress
""";

        var json = await RunPowerShellAsync(
            script, null, cancellationToken).ConfigureAwait(false);

        return JsonSerializer.Deserialize<DnsAdapterSnapshotR40>(
            json, ServiceMessageSerializer.Options)
            ?? throw new InvalidDataException(
                "Windows adapter discovery returned no snapshot.");
    }

    private async Task SetAdapterDnsLoopbackAsync(
        int interfaceIndex,
        CancellationToken cancellationToken)
    {
        const string script = """
$ErrorActionPreference = 'Stop'
$p = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($env:QS_PAYLOAD)) | ConvertFrom-Json
Set-DnsClientServerAddress -InterfaceIndex ([int]$p.interfaceIndex) -ServerAddresses @('127.0.0.1') -ErrorAction Stop
Clear-DnsClientCache -ErrorAction Stop
'OK'
""";

        await RunPowerShellAsync(
            script, new { interfaceIndex }, cancellationToken).ConfigureAwait(false);
    }

    private async Task RestoreOriginalDnsAsync(
        DnsAdapterSnapshotR40 original,
        CancellationToken cancellationToken)
    {
        const string script = """
$ErrorActionPreference = 'Stop'
$p = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($env:QS_PAYLOAD)) | ConvertFrom-Json
if ([bool]$p.automatic) {
    Set-DnsClientServerAddress -InterfaceIndex ([int]$p.interfaceIndex) -ResetServerAddresses -ErrorAction Stop
}
else {
    $servers = @($p.serverAddresses | ForEach-Object { [string]$_ })
    if ($servers.Count -eq 0) { throw 'Static DNS backup has no server addresses.' }
    Set-DnsClientServerAddress -InterfaceIndex ([int]$p.interfaceIndex) -ServerAddresses $servers -ErrorAction Stop
}
Clear-DnsClientCache -ErrorAction Stop
'OK'
""";

        await RunPowerShellAsync(
            script, original, cancellationToken).ConfigureAwait(false);
    }

    private async Task<bool> AdapterUsesLoopbackAsync(
        int interfaceIndex,
        CancellationToken cancellationToken)
    {
        try
        {
const string script = """
$ErrorActionPreference = 'Stop'
$p = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($env:QS_PAYLOAD)) | ConvertFrom-Json
$servers = @(
    (Get-DnsClientServerAddress -InterfaceIndex ([int]$p.interfaceIndex) -AddressFamily IPv4 -ErrorAction Stop).ServerAddresses
)
[pscustomobject]@{
    loopback = ($servers.Count -eq 1 -and [string]$servers[0] -eq '127.0.0.1')
} | ConvertTo-Json -Compress
""";

        var json = await RunPowerShellAsync(
            script, new { interfaceIndex }, cancellationToken).ConfigureAwait(false);

        using var document = JsonDocument.Parse(json);
        return document.RootElement.GetProperty("loopback").GetBoolean();
        }
        catch (InvalidOperationException exception) when (
            exception.Message.Contains("Get-DnsClientServerAddress", StringComparison.OrdinalIgnoreCase) &&
            exception.Message.Contains("No matching MSFT_DNSClientServerAddress objects found", StringComparison.OrdinalIgnoreCase))
        {
            // R4.2.11 stale adapter exception guard: a saved interface index can
            // disappear after VPN/adapter/device changes. Treat only this exact
            // CIM-not-found condition as "not loopback"; never guess another index.
            return false;
        }
    }    private async Task ApplyProfileRulesAsync(
        IReadOnlyList<ProfileFirewallRuleR40> rules,
        CancellationToken cancellationToken)
    {
        const string script = """
$ErrorActionPreference = 'Stop'
$p = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($env:QS_PAYLOAD)) | ConvertFrom-Json

$owned = @(
    Get-NetFirewallRule -PolicyStore ActiveStore -ErrorAction SilentlyContinue |
    Where-Object { $_.DisplayName -like 'QuietShield.Profile.*' }
)

foreach ($rule in $owned) {
    Remove-NetFirewallRule -Name $rule.Name -ErrorAction Stop
}

foreach ($item in @($p.rules)) {
    $path = [IO.Path]::GetFullPath([string]$item.executablePath)
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) { continue }

    New-NetFirewallRule `
        -DisplayName ([string]$item.ruleName) `
        -Name ([string]$item.ruleName) `
        -Direction Outbound `
        -Action Block `
        -Program $path `
        -Profile Any `
        -Enabled True `
        -Description 'QuietShield restrictive profile rule. Exact app path only.' `
        -ErrorAction Stop | Out-Null
}
'OK'
""";

        await RunPowerShellAsync(
            script, new { rules }, cancellationToken).ConfigureAwait(false);
    }

    private async Task<DnsShieldStateR40> LoadDnsStateAsync(
        CancellationToken cancellationToken)
    {
        if (!File.Exists(_dnsStatePath))
            return _dnsState;

        try
        {
            return await _dnsStateStore.ReadValidatedAsync(
                _dnsStatePath, cancellationToken).ConfigureAwait(false);
        }
        catch (Exception exception) when (
            exception is IOException or
            InvalidDataException or
            UnauthorizedAccessException or
            NotSupportedException)
        {
            return _dnsState with
            {
                Detail =
                    "DNS state could not be validated; no automatic adapter mutation was performed."
            };
        }
    }

    private Task SaveDnsStateAsync(
        DnsShieldStateR40 state,
        CancellationToken cancellationToken) =>
        _dnsStateStore.SaveAsync(_dnsStatePath, state, cancellationToken);

    private async Task<ProfileFirewallStateR40> LoadProfileStateAsync(
        CancellationToken cancellationToken)
    {
        if (!File.Exists(_profileStatePath))
            return _profileState;

        try
        {
            await using var stream = new FileStream(
                _profileStatePath,
                FileMode.Open,
                FileAccess.Read,
                FileShare.Read,
                4096,
                FileOptions.Asynchronous);

            return await JsonSerializer.DeserializeAsync<ProfileFirewallStateR40>(
                stream,
                ServiceMessageSerializer.Options,
                cancellationToken).ConfigureAwait(false)
                ?? _profileState;
        }
        catch (Exception exception) when (
            exception is IOException or UnauthorizedAccessException or JsonException)
        {
            return _profileState;
        }
    }

    private async Task SaveProfileStateAsync(
        ProfileFirewallStateR40 state,
        CancellationToken cancellationToken)
    {
        var directory = Path.GetDirectoryName(_profileStatePath)!;
        Directory.CreateDirectory(directory);

        var temporary =
            _profileStatePath + "." + Guid.NewGuid().ToString("N") + ".tmp";

        try
        {
            await File.WriteAllTextAsync(
                temporary,
                JsonSerializer.Serialize(state, ServiceMessageSerializer.Options),
                cancellationToken).ConfigureAwait(false);

            File.Move(temporary, _profileStatePath, true);
        }
        finally
        {
            if (File.Exists(temporary))
                File.Delete(temporary);
        }
    }

    private static string CreateProfileRuleName(
        string stableId,
        string path)
    {
        var bytes = SHA256.HashData(
            Encoding.UTF8.GetBytes(
                stableId + "\n" + path.ToUpperInvariant()));

        return "QuietShield.Profile." + Convert.ToHexString(bytes)[..24];
    }

    private static async Task<string> RunPowerShellAsync(
        string script,
        object? payload,
        CancellationToken cancellationToken)
    {
        var powershell = Path.Combine(
            Environment.SystemDirectory,
            "WindowsPowerShell",
            "v1.0",
            "powershell.exe");

        if (!File.Exists(powershell))
            powershell = Path.Combine(Environment.SystemDirectory, "powershell.exe");

        using var process = new Process
        {
            StartInfo = new ProcessStartInfo
            {
                FileName = powershell,
                UseShellExecute = false,
                CreateNoWindow = true,
                RedirectStandardOutput = true,
                RedirectStandardError = true
            }
        };

        process.StartInfo.ArgumentList.Add("-NoProfile");
        process.StartInfo.ArgumentList.Add("-NonInteractive");
        process.StartInfo.ArgumentList.Add("-ExecutionPolicy");
        process.StartInfo.ArgumentList.Add("Bypass");
        process.StartInfo.ArgumentList.Add("-Command");
        process.StartInfo.ArgumentList.Add(script);

        if (payload is not null)
        {
            process.StartInfo.Environment["QS_PAYLOAD"] =
                Convert.ToBase64String(
                    JsonSerializer.SerializeToUtf8Bytes(
                        payload, ServiceMessageSerializer.Options));
        }

        if (!process.Start())
            throw new InvalidOperationException(
                "Windows PowerShell could not be started.");

        var outputTask = process.StandardOutput.ReadToEndAsync(cancellationToken);
        var errorTask = process.StandardError.ReadToEndAsync(cancellationToken);

        await process.WaitForExitAsync(cancellationToken).ConfigureAwait(false);

        var output = (await outputTask.ConfigureAwait(false)).Trim();
        var error = (await errorTask.ConfigureAwait(false)).Trim();

        if (process.ExitCode != 0)
        {
            throw new InvalidOperationException(
                string.IsNullOrWhiteSpace(error)
                    ? "Windows PowerShell backend operation failed with exit code " +
                      process.ExitCode.ToString(CultureInfo.InvariantCulture) + "."
                    : error);
        }

        return output;
    }
}
#pragma warning restore CA1822
