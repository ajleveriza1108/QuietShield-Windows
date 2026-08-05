using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace QuietShield.Core.Dns;

public enum DnsTransactionState
{
    Created,
    PreflightPassed,
    BackupValidated,
    ReadyForApproval,
    Applying,
    Verifying,
    Committed,
    RollbackRequired,
    RollingBack,
    RolledBack,
    Interrupted,
    RecoveryRequired,
    Failed
}

public enum DnsRecoveryReason
{
    VerificationFailure,
    LastKnownGood,
    InterruptedTransaction,
    EmergencyManualRestore
}

public sealed record DnsAdapterIdentity(Guid InterfaceGuid, int InterfaceIndex);

public sealed record DnsAdapterOriginalState(
    DnsAdapterIdentity Identity,
    bool Automatic,
    IReadOnlyList<string> ServerAddresses);

public sealed record DnsBackupDocument(
    int SchemaVersion,
    string ProductMarker,
    string Purpose,
    Guid BackupId,
    DateTimeOffset CreatedAtUtc,
    IReadOnlyList<DnsAdapterOriginalState> Adapters,
    string PayloadSha256);

public sealed record DnsBackupValidation(bool Succeeded, string Status, DnsBackupDocument? Document);

public static class DnsBackupSerializer
{
    public const int CurrentSchemaVersion = 1;
    public const string ProductMarker = "QuietShield";
    public const string Purpose = "OriginalDnsBackup";
    private static readonly JsonSerializerOptions Options = CreateOptions();

    public static DnsBackupDocument Create(
        IEnumerable<DnsAdapterOriginalState> adapters,
        DateTimeOffset createdAtUtc,
        Guid? backupId = null)
    {
        ArgumentNullException.ThrowIfNull(adapters);
        var snapshot = adapters.Select(static adapter => adapter with
        {
            ServerAddresses = adapter.ServerAddresses.ToArray()
        }).ToArray();
        var document = new DnsBackupDocument(
            CurrentSchemaVersion,
            ProductMarker,
            Purpose,
            backupId ?? Guid.NewGuid(),
            createdAtUtc,
            snapshot,
            string.Empty);
        var validation = ValidateStructure(document, requireHash: false);
        if (!validation.Succeeded) throw new ArgumentException(validation.Status, nameof(adapters));
        return document with { PayloadSha256 = ComputePayloadSha256(document) };
    }

    public static string Serialize(DnsBackupDocument document)
    {
        var validation = Validate(document);
        if (!validation.Succeeded) throw new InvalidOperationException(validation.Status);
        return JsonSerializer.Serialize(document, Options);
    }

    public static DnsBackupValidation DeserializeAndValidate(string json)
    {
        if (string.IsNullOrWhiteSpace(json)) return Failed("The DNS backup is empty.");
        try
        {
            var document = JsonSerializer.Deserialize<DnsBackupDocument>(json, Options);
            return document is null ? Failed("The DNS backup document is missing.") : Validate(document);
        }
        catch (JsonException exception)
        {
            return Failed($"The DNS backup JSON is malformed: {exception.Message}");
        }
    }

    public static DnsBackupValidation Validate(DnsBackupDocument document)
    {
        ArgumentNullException.ThrowIfNull(document);
        var structure = ValidateStructure(document, requireHash: true);
        if (!structure.Succeeded) return structure;
        var computed = ComputePayloadSha256(document);
        if (!FixedTimeEquals(computed, document.PayloadSha256)) return Failed("The DNS backup payload hash is invalid.");
        return new DnsBackupValidation(true, "The QuietShield-created DNS backup is valid.", document with
        {
            Adapters = document.Adapters.Select(static adapter => adapter with { ServerAddresses = adapter.ServerAddresses.ToArray() }).ToArray()
        });
    }

    public static string ComputePayloadSha256(DnsBackupDocument document)
    {
        var canonical = new StringBuilder()
            .Append(document.SchemaVersion).Append('|')
            .Append(document.ProductMarker).Append('|')
            .Append(document.Purpose).Append('|')
            .Append(document.BackupId.ToString("D")).Append('|')
            .Append(document.CreatedAtUtc.ToUniversalTime().ToString("O", System.Globalization.CultureInfo.InvariantCulture)).Append('\n');
        foreach (var adapter in document.Adapters.OrderBy(static item => item.Identity.InterfaceGuid).ThenBy(static item => item.Identity.InterfaceIndex))
        {
            canonical.Append(adapter.Identity.InterfaceGuid.ToString("D")).Append('|')
                .Append(adapter.Identity.InterfaceIndex).Append('|')
                .Append(adapter.Automatic ? "Automatic" : "Static").Append('|')
                .AppendJoin(',', adapter.ServerAddresses).Append('\n');
        }

        return Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(canonical.ToString())));
    }

    private static DnsBackupValidation ValidateStructure(DnsBackupDocument document, bool requireHash)
    {
        if (document.SchemaVersion != CurrentSchemaVersion ||
            !document.ProductMarker.Equals(ProductMarker, StringComparison.Ordinal) ||
            !document.Purpose.Equals(Purpose, StringComparison.Ordinal))
            return Failed("The DNS backup is not a supported QuietShield original-DNS backup.");
        if (document.BackupId == Guid.Empty) return Failed("The DNS backup identifier is invalid.");
        if (document.CreatedAtUtc == default) return Failed("The DNS backup creation timestamp is invalid.");
        if (document.Adapters is null || document.Adapters.Count == 0) return Failed("The DNS backup contains no adapters.");

        var identities = new HashSet<DnsAdapterIdentity>();
        foreach (var adapter in document.Adapters)
        {
            if (adapter.Identity.InterfaceGuid == Guid.Empty || adapter.Identity.InterfaceIndex <= 0)
                return Failed("The DNS backup contains an invalid adapter identity.");
            if (!identities.Add(adapter.Identity)) return Failed("The DNS backup contains a duplicate adapter identity.");
            if (adapter.ServerAddresses is null) return Failed("The DNS backup contains a missing server-address collection.");
            if (adapter.ServerAddresses.Any(static address => !IPAddress.TryParse(address, out _)))
                return Failed("The DNS backup contains a non-IP DNS server value.");
            if (adapter.ServerAddresses.Distinct(StringComparer.OrdinalIgnoreCase).Count() != adapter.ServerAddresses.Count)
                return Failed("The DNS backup contains duplicate DNS server values.");
            if (!adapter.Automatic && adapter.ServerAddresses.Count == 0)
                return Failed("A static DNS backup entry must contain its original DNS server values.");
        }

        if (requireHash && (document.PayloadSha256?.Length != 64 || !document.PayloadSha256.All(Uri.IsHexDigit)))
            return Failed("The DNS backup payload hash has an invalid format.");
        return new DnsBackupValidation(true, "The DNS backup structure is valid.", document);
    }

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

    private static DnsBackupValidation Failed(string status) => new(false, status, null);
}

public sealed record DnsTransactionPreflightResult(
    bool Succeeded,
    IReadOnlyList<DnsAdapterIdentity> ActiveAdapters,
    string Status);

public sealed record DnsActivationAuthorization(
    bool ExplicitUserApproval,
    bool AdministratorContext,
    bool ValidatedBackup,
    bool ActiveLocalResolver,
    DateTimeOffset VerificationDeadlineUtc);

public sealed record DnsActivationPlan(
    Guid TransactionId,
    DnsTransactionState State,
    DnsBackupDocument OriginalDnsBackup,
    DnsEndpointIdentity ProposedLocalResolver,
    IReadOnlyList<DnsAdapterIdentity> TargetAdapters,
    DateTimeOffset CreatedAtUtc,
    string Status);

public sealed record DnsTransactionResult(
    bool Succeeded,
    DnsTransactionState State,
    string Status,
    bool RollbackAttempted,
    bool RollbackSucceeded);

public sealed record DnsTransactionReadiness(
    bool Ready,
    IReadOnlyList<string> MissingRequirements,
    string Status);

public static class DnsTransactionReadinessEvaluator
{
    public static DnsTransactionReadiness Evaluate(
        bool explicitUserApproval,
        bool administratorContext,
        bool validatedBackup,
        bool activeLocalResolver,
        bool activeAdaptersSelected)
    {
        var missing = new List<string>();
        if (!explicitUserApproval) missing.Add("explicit user approval");
        if (!administratorContext) missing.Add("Administrator context");
        if (!validatedBackup) missing.Add("validated original-DNS backup");
        if (!activeLocalResolver) missing.Add("active local QuietShield resolver");
        if (!activeAdaptersSelected) missing.Add("validated active-adapter selection");
        return missing.Count == 0
            ? new DnsTransactionReadiness(true, Array.Empty<string>(), "All activation prerequisites are present; execution still requires a separately approved activation phase.")
            : new DnsTransactionReadiness(false, missing, "DNS activation is not ready: " + string.Join(", ", missing) + ".");
    }
}

public sealed record DnsRecoveryPlan(
    Guid RecoveryId,
    Guid TransactionId,
    DnsRecoveryReason Reason,
    DnsBackupDocument ValidatedBackup,
    IReadOnlyList<DnsAdapterIdentity> TargetAdapters,
    bool RequiresAdministrator,
    bool RequiresExplicitApproval,
    string Status);

public interface IDnsTransactionPreflight
{
    Task<DnsTransactionPreflightResult> RunAsync(CancellationToken cancellationToken);
}

public interface IDnsOriginalConfigurationSource
{
    Task<IReadOnlyList<DnsAdapterOriginalState>> CaptureAsync(IReadOnlyList<DnsAdapterIdentity> adapters, CancellationToken cancellationToken);
}

public interface IDnsBackupRepository
{
    Task SaveValidatedAsync(DnsBackupDocument backup, CancellationToken cancellationToken);
    Task<DnsBackupDocument?> LoadLastKnownGoodAsync(CancellationToken cancellationToken);
}

public interface IDnsTransactionJournal
{
    Task SaveAsync(DnsActivationPlan plan, CancellationToken cancellationToken);
    Task<DnsActivationPlan?> LoadInterruptedAsync(CancellationToken cancellationToken);
}

public interface IDnsConfigurationMutator
{
    Task ApplyAsync(DnsActivationPlan plan, CancellationToken cancellationToken);
    Task RestoreAsync(DnsRecoveryPlan recoveryPlan, CancellationToken cancellationToken);
}

public interface IDnsCacheFlushOperation
{
    Task FlushAsync(CancellationToken cancellationToken);
}

public interface IDnsConnectivityVerifier
{
    Task<bool> VerifyAsync(DateTimeOffset deadlineUtc, CancellationToken cancellationToken);
}

public interface IQuietShieldResolverVerifier
{
    Task<bool> VerifyAsync(DnsEndpointIdentity endpoint, DateTimeOffset deadlineUtc, CancellationToken cancellationToken);
}

public sealed class DnsTransactionStateMachine
{
    private static readonly Dictionary<DnsTransactionState, DnsTransactionState[]> AllowedTransitions =
        new Dictionary<DnsTransactionState, DnsTransactionState[]>
        {
            [DnsTransactionState.Created] = new[] { DnsTransactionState.PreflightPassed, DnsTransactionState.Failed },
            [DnsTransactionState.PreflightPassed] = new[] { DnsTransactionState.BackupValidated, DnsTransactionState.Failed },
            [DnsTransactionState.BackupValidated] = new[] { DnsTransactionState.ReadyForApproval, DnsTransactionState.Failed },
            [DnsTransactionState.ReadyForApproval] = new[] { DnsTransactionState.Applying, DnsTransactionState.Failed },
            [DnsTransactionState.Applying] = new[] { DnsTransactionState.Verifying, DnsTransactionState.RollbackRequired, DnsTransactionState.Interrupted },
            [DnsTransactionState.Verifying] = new[] { DnsTransactionState.Committed, DnsTransactionState.RollbackRequired, DnsTransactionState.Interrupted },
            [DnsTransactionState.RollbackRequired] = new[] { DnsTransactionState.RollingBack, DnsTransactionState.RecoveryRequired },
            [DnsTransactionState.RollingBack] = new[] { DnsTransactionState.RolledBack, DnsTransactionState.RecoveryRequired },
            [DnsTransactionState.Interrupted] = new[] { DnsTransactionState.RecoveryRequired },
            [DnsTransactionState.RecoveryRequired] = new[] { DnsTransactionState.RollingBack },
            [DnsTransactionState.Committed] = Array.Empty<DnsTransactionState>(),
            [DnsTransactionState.RolledBack] = Array.Empty<DnsTransactionState>(),
            [DnsTransactionState.Failed] = Array.Empty<DnsTransactionState>()
        };

    public DnsTransactionState Current { get; private set; } = DnsTransactionState.Created;

    public void TransitionTo(DnsTransactionState next)
    {
        if (!AllowedTransitions[Current].Contains(next)) throw new InvalidOperationException($"DNS transaction cannot transition from {Current} to {next}.");
        Current = next;
    }
}

public static class DnsAdapterIdentityMatcher
{
    public static bool Matches(DnsAdapterIdentity expected, DnsAdapterIdentity actual) =>
        expected.InterfaceGuid != Guid.Empty &&
        expected.InterfaceGuid == actual.InterfaceGuid &&
        expected.InterfaceIndex == actual.InterfaceIndex;
}

public static class DnsRecoveryPlanner
{
    public static DnsRecoveryPlan Create(Guid transactionId, DnsRecoveryReason reason, DnsBackupDocument backup)
    {
        var validation = DnsBackupSerializer.Validate(backup);
        if (!validation.Succeeded || validation.Document is null) throw new InvalidOperationException(validation.Status);
        return new DnsRecoveryPlan(
            Guid.NewGuid(),
            transactionId,
            reason,
            validation.Document,
            validation.Document.Adapters.Select(static adapter => adapter.Identity).ToArray(),
            true,
            true,
            "Recovery requires explicit approval, Administrator context, and exact adapter identity matching.");
    }
}

public sealed class DnsTransactionCoordinator
{
    private readonly IDnsTransactionPreflight _preflight;
    private readonly IDnsOriginalConfigurationSource _configuration;
    private readonly IDnsBackupRepository _backups;
    private readonly IDnsTransactionJournal _journal;
    private readonly IDnsConfigurationMutator _mutator;
    private readonly IDnsCacheFlushOperation _cacheFlush;
    private readonly IDnsConnectivityVerifier _connectivity;
    private readonly IQuietShieldResolverVerifier _resolver;

    public DnsTransactionCoordinator(
        IDnsTransactionPreflight preflight,
        IDnsOriginalConfigurationSource configuration,
        IDnsBackupRepository backups,
        IDnsTransactionJournal journal,
        IDnsConfigurationMutator mutator,
        IDnsCacheFlushOperation cacheFlush,
        IDnsConnectivityVerifier connectivity,
        IQuietShieldResolverVerifier resolver)
    {
        _preflight = preflight;
        _configuration = configuration;
        _backups = backups;
        _journal = journal;
        _mutator = mutator;
        _cacheFlush = cacheFlush;
        _connectivity = connectivity;
        _resolver = resolver;
    }

    public async Task<DnsActivationPlan> PrepareAsync(DnsEndpointIdentity proposedResolver, DateTimeOffset nowUtc, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(proposedResolver);
        var state = new DnsTransactionStateMachine();
        var preflight = await _preflight.RunAsync(cancellationToken).ConfigureAwait(false);
        if (!preflight.Succeeded || preflight.ActiveAdapters.Count == 0) throw new InvalidOperationException(preflight.Status);
        state.TransitionTo(DnsTransactionState.PreflightPassed);
        var original = await _configuration.CaptureAsync(preflight.ActiveAdapters, cancellationToken).ConfigureAwait(false);
        var backup = DnsBackupSerializer.Create(original, nowUtc);
        var validation = DnsBackupSerializer.Validate(backup);
        if (!validation.Succeeded) throw new InvalidOperationException(validation.Status);
        await _backups.SaveValidatedAsync(backup, cancellationToken).ConfigureAwait(false);
        state.TransitionTo(DnsTransactionState.BackupValidated);
        state.TransitionTo(DnsTransactionState.ReadyForApproval);
        var plan = new DnsActivationPlan(
            Guid.NewGuid(), state.Current, backup, proposedResolver, preflight.ActiveAdapters.ToArray(), nowUtc,
            "Preview only. Execution requires explicit approval, Administrator context, an active local resolver, and a verification deadline.");
        await _journal.SaveAsync(plan, cancellationToken).ConfigureAwait(false);
        return plan;
    }

    public async Task<DnsTransactionResult> ExecuteAsync(DnsActivationPlan plan, DnsActivationAuthorization authorization, DateTimeOffset nowUtc, CancellationToken cancellationToken)
    {
        var guardFailure = ValidateExecutionGuard(plan, authorization, nowUtc);
        if (guardFailure is not null) return new DnsTransactionResult(false, plan.State, guardFailure, false, false);

        var state = new DnsTransactionStateMachine();
        state.TransitionTo(DnsTransactionState.PreflightPassed);
        state.TransitionTo(DnsTransactionState.BackupValidated);
        state.TransitionTo(DnsTransactionState.ReadyForApproval);
        state.TransitionTo(DnsTransactionState.Applying);
        await _journal.SaveAsync(plan with { State = state.Current }, cancellationToken).ConfigureAwait(false);
        try
        {
            await _mutator.ApplyAsync(plan, cancellationToken).ConfigureAwait(false);
            await _cacheFlush.FlushAsync(cancellationToken).ConfigureAwait(false);
            state.TransitionTo(DnsTransactionState.Verifying);
            await _journal.SaveAsync(plan with { State = state.Current }, cancellationToken).ConfigureAwait(false);
            var resolverSucceeded = await _resolver.VerifyAsync(plan.ProposedLocalResolver, authorization.VerificationDeadlineUtc, cancellationToken).ConfigureAwait(false);
            var connectivitySucceeded = resolverSucceeded && await _connectivity.VerifyAsync(authorization.VerificationDeadlineUtc, cancellationToken).ConfigureAwait(false);
            if (!resolverSucceeded || !connectivitySucceeded) throw new InvalidOperationException("DNS activation verification failed before the deadline.");
            state.TransitionTo(DnsTransactionState.Committed);
            await _journal.SaveAsync(plan with { State = state.Current }, cancellationToken).ConfigureAwait(false);
            return new DnsTransactionResult(true, state.Current, "The DNS transaction was verified and committed.", false, false);
        }
        catch (Exception exception) when (exception is IOException or InvalidOperationException or TimeoutException or OperationCanceledException)
        {
            state.TransitionTo(DnsTransactionState.RollbackRequired);
            await _journal.SaveAsync(plan with { State = state.Current, Status = exception.Message }, CancellationToken.None).ConfigureAwait(false);
            state.TransitionTo(DnsTransactionState.RollingBack);
            try
            {
                var recovery = DnsRecoveryPlanner.Create(plan.TransactionId, DnsRecoveryReason.VerificationFailure, plan.OriginalDnsBackup);
                await _mutator.RestoreAsync(recovery, CancellationToken.None).ConfigureAwait(false);
                await _cacheFlush.FlushAsync(CancellationToken.None).ConfigureAwait(false);
                state.TransitionTo(DnsTransactionState.RolledBack);
                await _journal.SaveAsync(plan with { State = state.Current }, CancellationToken.None).ConfigureAwait(false);
                return new DnsTransactionResult(false, state.Current, exception.Message, true, true);
            }
            catch (Exception rollbackException) when (rollbackException is IOException or InvalidOperationException or TimeoutException or OperationCanceledException)
            {
                state.TransitionTo(DnsTransactionState.RecoveryRequired);
                await _journal.SaveAsync(plan with { State = state.Current, Status = rollbackException.Message }, CancellationToken.None).ConfigureAwait(false);
                return new DnsTransactionResult(false, state.Current, rollbackException.Message, true, false);
            }
        }
    }

    public async Task<DnsRecoveryPlan?> PlanInterruptedRecoveryAsync(CancellationToken cancellationToken)
    {
        var interrupted = await _journal.LoadInterruptedAsync(cancellationToken).ConfigureAwait(false);
        if (interrupted is null) return null;
        return DnsRecoveryPlanner.Create(interrupted.TransactionId, DnsRecoveryReason.InterruptedTransaction, interrupted.OriginalDnsBackup);
    }

    public async Task<DnsRecoveryPlan?> PlanLastKnownGoodRecoveryAsync(Guid transactionId, CancellationToken cancellationToken)
    {
        var backup = await _backups.LoadLastKnownGoodAsync(cancellationToken).ConfigureAwait(false);
        return backup is null ? null : DnsRecoveryPlanner.Create(transactionId, DnsRecoveryReason.LastKnownGood, backup);
    }

    private static string? ValidateExecutionGuard(DnsActivationPlan plan, DnsActivationAuthorization authorization, DateTimeOffset nowUtc)
    {
        if (plan.State != DnsTransactionState.ReadyForApproval) return "The DNS transaction plan is not ready for approval.";
        if (!authorization.ExplicitUserApproval) return "Explicit user approval is required before a DNS change.";
        if (!authorization.AdministratorContext) return "Administrator context is required before a DNS change.";
        if (!authorization.ValidatedBackup || !DnsBackupSerializer.Validate(plan.OriginalDnsBackup).Succeeded) return "A validated original-DNS backup is required before a DNS change.";
        if (!authorization.ActiveLocalResolver) return "An active QuietShield local resolver is required before a DNS change.";
        if (authorization.VerificationDeadlineUtc <= nowUtc || authorization.VerificationDeadlineUtc > nowUtc.AddMinutes(5)) return "A bounded future verification deadline is required before a DNS change.";
        if (plan.TargetAdapters.Count == 0 || plan.TargetAdapters.Any(target => plan.OriginalDnsBackup.Adapters.All(original => !DnsAdapterIdentityMatcher.Matches(target, original.Identity))))
            return "Every target adapter must match the validated original-DNS backup.";
        return null;
    }
}
