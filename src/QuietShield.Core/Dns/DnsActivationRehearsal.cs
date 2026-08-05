using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace QuietShield.Core.Dns;

public enum DnsRehearsalState
{
    Prepared,
    WatchdogStarted,
    ResolverStarted,
    DnsChanged,
    VerificationPassed,
    RehearsalActive,
    RollbackStarted,
    DnsRestored,
    PostRestoreVerified,
    Completed
}

public enum DnsRehearsalAdapterKind
{
    Ethernet,
    WiFi,
    Vpn,
    Virtual,
    Other
}

public enum DnsRehearsalAddressFamily
{
    IPv4,
    IPv6
}

public enum DnsWatchdogTrigger
{
    None,
    ApprovedDurationElapsed,
    HeartbeatLost,
    HostExited,
    OrchestratorExited,
    ConnectivityFailed,
    OrchestratorRequestedRollback
}

public sealed record DnsRehearsalAdapterCandidate(
    DnsAdapterIdentity Identity,
    DnsRehearsalAdapterKind Kind,
    bool IsPhysical,
    bool IsActive,
    bool IsVirtual,
    bool IsSupported);

public sealed record DnsRehearsalAdapterSelection(
    bool Succeeded,
    DnsRehearsalAdapterCandidate? Adapter,
    string Status);

public static class DnsRehearsalAdapterSelector
{
    public static DnsRehearsalAdapterSelection SelectExactlyOne(IEnumerable<DnsRehearsalAdapterCandidate> candidates)
    {
        ArgumentNullException.ThrowIfNull(candidates);
        var eligible = candidates.Where(static candidate =>
            candidate.IsPhysical &&
            candidate.IsActive &&
            !candidate.IsVirtual &&
            candidate.IsSupported &&
            candidate.Kind is DnsRehearsalAdapterKind.Ethernet or DnsRehearsalAdapterKind.WiFi).ToArray();
        return eligible.Length switch
        {
            1 => new DnsRehearsalAdapterSelection(true, eligible[0], "Exactly one active supported physical adapter was selected."),
            0 => new DnsRehearsalAdapterSelection(false, null, "No active supported physical Wi-Fi or Ethernet adapter is available."),
            _ => new DnsRehearsalAdapterSelection(false, null, "Adapter selection is ambiguous; more than one active supported physical adapter is available.")
        };
    }
}

public sealed record DnsRehearsalFamilySnapshot(
    DnsRehearsalAddressFamily AddressFamily,
    bool Enabled,
    bool Automatic,
    IReadOnlyList<string> ServerAddresses);

public sealed record DnsRehearsalAdapterSnapshot(
    DnsAdapterIdentity Identity,
    DnsRehearsalAdapterKind Kind,
    IReadOnlyList<DnsRehearsalFamilySnapshot> Families);

public sealed record DnsRehearsalBackupDocument(
    int SchemaVersion,
    string ProductMarker,
    string Purpose,
    Guid BackupId,
    Guid RehearsalId,
    DateTimeOffset CreatedAtUtc,
    DnsRehearsalAdapterSnapshot Adapter,
    string PayloadSha256);

public sealed record DnsRehearsalBackupValidation(bool Succeeded, string Status, DnsRehearsalBackupDocument? Document);

public static class DnsRehearsalBackupSerializer
{
    public const int SchemaVersion = 1;
    public const string ProductMarker = "QuietShield";
    public const string Purpose = "DnsActivationRehearsalBackup";
    private static readonly JsonSerializerOptions Options = CreateOptions();

    public static DnsRehearsalBackupDocument Create(
        Guid rehearsalId,
        DnsRehearsalAdapterSnapshot adapter,
        DateTimeOffset createdAtUtc,
        Guid? backupId = null)
    {
        var document = new DnsRehearsalBackupDocument(
            SchemaVersion,
            ProductMarker,
            Purpose,
            backupId ?? Guid.NewGuid(),
            rehearsalId,
            createdAtUtc,
            Copy(adapter),
            string.Empty);
        var structure = ValidateStructure(document, false);
        if (!structure.Succeeded) throw new ArgumentException(structure.Status, nameof(adapter));
        return document with { PayloadSha256 = ComputePayloadSha256(document) };
    }

    public static string Serialize(DnsRehearsalBackupDocument document)
    {
        var validation = Validate(document);
        if (!validation.Succeeded) throw new InvalidOperationException(validation.Status);
        return JsonSerializer.Serialize(validation.Document, Options);
    }

    public static DnsRehearsalBackupValidation DeserializeAndValidate(string json)
    {
        if (string.IsNullOrWhiteSpace(json)) return Failed("The rehearsal backup is empty.");
        try
        {
            var document = JsonSerializer.Deserialize<DnsRehearsalBackupDocument>(json, Options);
            return document is null ? Failed("The rehearsal backup document is missing.") : Validate(document);
        }
        catch (JsonException exception)
        {
            return Failed($"The rehearsal backup JSON is malformed: {exception.Message}");
        }
    }

    public static DnsRehearsalBackupValidation Validate(DnsRehearsalBackupDocument document)
    {
        ArgumentNullException.ThrowIfNull(document);
        var structure = ValidateStructure(document, true);
        if (!structure.Succeeded) return structure;
        var computed = ComputePayloadSha256(document);
        if (!FixedTimeEquals(computed, document.PayloadSha256)) return Failed("The rehearsal backup payload hash is invalid.");
        return new DnsRehearsalBackupValidation(true, "The QuietShield rehearsal backup is valid.", document with { Adapter = Copy(document.Adapter) });
    }

    public static string ComputePayloadSha256(DnsRehearsalBackupDocument document)
    {
        var canonical = new StringBuilder()
            .Append(document.SchemaVersion).Append('|')
            .Append(document.ProductMarker).Append('|')
            .Append(document.Purpose).Append('|')
            .Append(document.BackupId.ToString("D")).Append('|')
            .Append(document.RehearsalId.ToString("D")).Append('|')
            .Append(document.CreatedAtUtc.ToUniversalTime().ToString("O", System.Globalization.CultureInfo.InvariantCulture)).Append('\n')
            .Append(document.Adapter.Identity.InterfaceGuid.ToString("D")).Append('|')
            .Append(document.Adapter.Identity.InterfaceIndex).Append('|')
            .Append(document.Adapter.Kind).Append('\n');
        foreach (var family in document.Adapter.Families.OrderBy(static item => item.AddressFamily))
        {
            canonical.Append(family.AddressFamily).Append('|')
                .Append(family.Enabled ? "Enabled" : "Disabled").Append('|')
                .Append(family.Automatic ? "Automatic" : "Static").Append('|')
                .AppendJoin(',', family.ServerAddresses).Append('\n');
        }

        return Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(canonical.ToString())));
    }

    private static DnsRehearsalBackupValidation ValidateStructure(DnsRehearsalBackupDocument document, bool requireHash)
    {
        if (document.SchemaVersion != SchemaVersion ||
            !document.ProductMarker.Equals(ProductMarker, StringComparison.Ordinal) ||
            !document.Purpose.Equals(Purpose, StringComparison.Ordinal))
            return Failed("The file is not a supported QuietShield DNS activation rehearsal backup.");
        if (document.BackupId == Guid.Empty || document.RehearsalId == Guid.Empty || document.CreatedAtUtc == default)
            return Failed("The rehearsal backup identity or timestamp is invalid.");
        if (document.Adapter is null || document.Adapter.Identity.InterfaceGuid == Guid.Empty || document.Adapter.Identity.InterfaceIndex <= 0)
            return Failed("The rehearsal backup adapter identity is invalid.");
        if (document.Adapter.Kind is not (DnsRehearsalAdapterKind.Ethernet or DnsRehearsalAdapterKind.WiFi))
            return Failed("The rehearsal backup adapter is not a supported physical type.");
        if (document.Adapter.Families is null || document.Adapter.Families.Count != 2 ||
            document.Adapter.Families.Select(static family => family.AddressFamily).Distinct().Count() != 2)
            return Failed("The rehearsal backup must contain exactly one IPv4 and one IPv6 state.");
        foreach (var family in document.Adapter.Families)
        {
            if (family.ServerAddresses is null) return Failed("The rehearsal backup contains a missing DNS server collection.");
            foreach (var server in family.ServerAddresses)
            {
                if (!IPAddress.TryParse(server, out var address)) return Failed("The rehearsal backup contains a non-IP DNS server value.");
                if (family.AddressFamily == DnsRehearsalAddressFamily.IPv4 && address.AddressFamily != System.Net.Sockets.AddressFamily.InterNetwork)
                    return Failed("An IPv4 backup contains a non-IPv4 server value.");
                if (family.AddressFamily == DnsRehearsalAddressFamily.IPv6 && address.AddressFamily != System.Net.Sockets.AddressFamily.InterNetworkV6)
                    return Failed("An IPv6 backup contains a non-IPv6 server value.");
            }
            if (family.Enabled && !family.Automatic && family.ServerAddresses.Count == 0)
                return Failed("An enabled static DNS family must contain its exact original server values.");
        }
        if (requireHash && (document.PayloadSha256?.Length != 64 || !document.PayloadSha256.All(Uri.IsHexDigit)))
            return Failed("The rehearsal backup hash format is invalid.");
        return new DnsRehearsalBackupValidation(true, "The rehearsal backup structure is valid.", document);
    }

    private static DnsRehearsalAdapterSnapshot Copy(DnsRehearsalAdapterSnapshot adapter) => adapter with
    {
        Families = adapter.Families.Select(static family => family with { ServerAddresses = family.ServerAddresses.ToArray() }).ToArray()
    };

    private static bool FixedTimeEquals(string first, string second)
    {
        if (first.Length != second.Length) return false;
        return CryptographicOperations.FixedTimeEquals(Encoding.ASCII.GetBytes(first), Encoding.ASCII.GetBytes(second));
    }

    private static JsonSerializerOptions CreateOptions()
    {
        var options = new JsonSerializerOptions(JsonSerializerDefaults.Web) { WriteIndented = true };
        options.Converters.Add(new JsonStringEnumConverter());
        return options;
    }

    private static DnsRehearsalBackupValidation Failed(string status) => new(false, status, null);
}

public sealed class DnsRehearsalStateMachine
{
    private static readonly Dictionary<DnsRehearsalState, DnsRehearsalState[]> Allowed = new()
    {
        [DnsRehearsalState.Prepared] = new[] { DnsRehearsalState.WatchdogStarted },
        [DnsRehearsalState.WatchdogStarted] = new[] { DnsRehearsalState.ResolverStarted },
        [DnsRehearsalState.ResolverStarted] = new[] { DnsRehearsalState.DnsChanged },
        [DnsRehearsalState.DnsChanged] = new[] { DnsRehearsalState.VerificationPassed, DnsRehearsalState.RollbackStarted },
        [DnsRehearsalState.VerificationPassed] = new[] { DnsRehearsalState.RehearsalActive, DnsRehearsalState.RollbackStarted },
        [DnsRehearsalState.RehearsalActive] = new[] { DnsRehearsalState.RollbackStarted },
        [DnsRehearsalState.RollbackStarted] = new[] { DnsRehearsalState.DnsRestored },
        [DnsRehearsalState.DnsRestored] = new[] { DnsRehearsalState.PostRestoreVerified },
        [DnsRehearsalState.PostRestoreVerified] = new[] { DnsRehearsalState.Completed },
        [DnsRehearsalState.Completed] = Array.Empty<DnsRehearsalState>()
    };

    public DnsRehearsalState Current { get; private set; } = DnsRehearsalState.Prepared;

    public void TransitionTo(DnsRehearsalState next)
    {
        if (!Allowed[Current].Contains(next)) throw new InvalidOperationException($"DNS rehearsal cannot transition from {Current} to {next}.");
        Current = next;
    }
}

public sealed record DnsWatchdogObservation(
    bool RollbackArmed,
    bool RollbackAlreadyCompleted,
    DateTimeOffset NowUtc,
    DateTimeOffset DeadlineUtc,
    bool HeartbeatStarted,
    DateTimeOffset? LastHeartbeatUtc,
    TimeSpan HeartbeatTimeout,
    bool HostStarted,
    bool HostAlive,
    bool OrchestratorAlive,
    bool ConnectivityCheckCompleted,
    bool ConnectivityHealthy,
    bool RollbackRequested);

public sealed record DnsWatchdogDecision(bool RestoreRequired, bool Stop, DnsWatchdogTrigger Trigger, string Status);

public static class DnsWatchdogDecisionEvaluator
{
    public static DnsWatchdogDecision Evaluate(DnsWatchdogObservation observation)
    {
        ArgumentNullException.ThrowIfNull(observation);
        if (observation.RollbackAlreadyCompleted) return new DnsWatchdogDecision(false, true, DnsWatchdogTrigger.None, "Restoration is already complete.");
        if (!observation.RollbackArmed) return new DnsWatchdogDecision(false, false, DnsWatchdogTrigger.None, "Rollback is not armed because DNS has not entered its change window.");
        if (observation.RollbackRequested) return Restore(DnsWatchdogTrigger.OrchestratorRequestedRollback, "The orchestrator requested immediate rollback.");
        if (observation.NowUtc >= observation.DeadlineUtc) return Restore(DnsWatchdogTrigger.ApprovedDurationElapsed, "The approved rehearsal duration elapsed.");
        if (!observation.OrchestratorAlive) return Restore(DnsWatchdogTrigger.OrchestratorExited, "The orchestration process exited unexpectedly.");
        if (observation.HostStarted && !observation.HostAlive) return Restore(DnsWatchdogTrigger.HostExited, "The DNS host exited unexpectedly.");
        if (observation.HeartbeatStarted && observation.LastHeartbeatUtc is not null && observation.NowUtc - observation.LastHeartbeatUtc > observation.HeartbeatTimeout)
            return Restore(DnsWatchdogTrigger.HeartbeatLost, "The DNS host heartbeat expired.");
        if (observation.ConnectivityCheckCompleted && !observation.ConnectivityHealthy)
            return Restore(DnsWatchdogTrigger.ConnectivityFailed, "Independent connectivity verification failed.");
        return new DnsWatchdogDecision(false, false, DnsWatchdogTrigger.None, "The watchdog continues monitoring.");
    }

    private static DnsWatchdogDecision Restore(DnsWatchdogTrigger trigger, string status) => new(true, false, trigger, status);
}

public static class DnsRehearsalDuration
{
    public static TimeSpan Validate(TimeSpan duration)
    {
        if (duration <= TimeSpan.Zero || duration > TimeSpan.FromSeconds(300)) throw new ArgumentOutOfRangeException(nameof(duration), "The rehearsal duration must be between 1 and 300 seconds.");
        return duration;
    }
}

public sealed record DnsRehearsalInvocationDecision(bool Allowed, string Status);

public static class DnsRehearsalInvocationGuard
{
    public static DnsRehearsalInvocationDecision Evaluate(bool anotherInvocationHoldsLock, bool approvedAttemptAlreadyRecorded)
    {
        if (anotherInvocationHoldsLock) return new DnsRehearsalInvocationDecision(false, "Another DNS activation rehearsal is already running.");
        if (approvedAttemptAlreadyRecorded) return new DnsRehearsalInvocationDecision(false, "This explicitly approved rehearsal attempt was already recorded. Repeated invocation is refused.");
        return new DnsRehearsalInvocationDecision(true, "This is the first and only eligible rehearsal invocation.");
    }
}

public static class DnsRehearsalActivationGuard
{
    public static bool CanChangeDns(DnsRehearsalState currentState, bool hostReady, bool watchdogReady, bool backupValidated) =>
        currentState == DnsRehearsalState.ResolverStarted && hostReady && watchdogReady && backupValidated;
}

public static class DnsRehearsalUpstreamSelector
{
    public static IReadOnlyList<string> SelectDistinctForwardingAddresses(DnsRehearsalBackupDocument backup)
    {
        ArgumentNullException.ThrowIfNull(backup);
        return backup.Adapter.Families
            .Where(static family => family.Enabled)
            .SelectMany(static family => family.ServerAddresses)
            .Where(static address => IPAddress.TryParse(address, out var parsed) && !IPAddress.IsLoopback(parsed))
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToArray();
    }
}

public sealed record DnsRehearsalPolicySnapshot(
    bool Loaded,
    string NormalizedBlockedTestDomain,
    DnsDecision TestDecision,
    string Status);

public sealed class DnsRehearsalPolicyEvaluator : IDnsRuntimePolicyEvaluator
{
    public const string BlockedTestDomain = "quietshield-blocked.test";
    private static readonly CustomDomainEntry BlockedTestEntry = new(
        Guid.Parse("55555555-5555-5555-5555-555555555555"),
        BlockedTestDomain,
        DnsRuleMatchKind.Exact,
        CustomDomainListKind.Blocklist,
        "Embedded safe Phase 5 rehearsal rule",
        DateTimeOffset.UnixEpoch,
        true);
    private static readonly CustomDomainEntry[] CustomEntries = { BlockedTestEntry };
    private static readonly string[] SafetyExemptions = { "recovery.quietshield.invalid" };
    private static readonly HashSet<DnsCategory> CustomCategories = new();

    public Task<DnsPolicyResult> EvaluateAsync(string normalizedDomain, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        return Task.FromResult(Evaluate(normalizedDomain));
    }

    public static DnsRehearsalPolicySnapshot GetSnapshot()
    {
        var normalization = DomainNormalizer.NormalizeDomain(BlockedTestDomain);
        if (!normalization.IsValid || normalization.NormalizedValue is null)
            return new DnsRehearsalPolicySnapshot(false, string.Empty, DnsDecision.Indeterminate, normalization.Error ?? "The embedded test domain is invalid.");
        var result = Evaluate(normalization.NormalizedValue);
        var loaded = result.Decision == DnsDecision.Block &&
                     result.NormalizedDomain == normalization.NormalizedValue &&
                     result.MatchedRule == normalization.NormalizedValue;
        return new DnsRehearsalPolicySnapshot(
            loaded,
            normalization.NormalizedValue,
            result.Decision,
            loaded ? "The embedded blocked-domain policy snapshot is fully loaded and normalized." : "The embedded blocked-domain policy snapshot is not ready.");
    }

    private static DnsPolicyResult Evaluate(string domain) => DnsPolicyEngine.Evaluate(new DnsPolicyRequest(
        domain,
        DnsProtectionMode.Standard,
        CustomCategories,
        null,
        CustomEntries,
        SafetyExemptions,
        DateTimeOffset.UtcNow));
}
