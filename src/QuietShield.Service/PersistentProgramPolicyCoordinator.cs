using System.Security.Cryptography;
using System.Text;
using QuietShield.Core.ConnectionLock;
using QuietShield.Core.ConnectionLock.Transactions;
using QuietShield.Core.Protection;
using QuietShield.Core.ServiceFoundation;

namespace QuietShield.Service;

public sealed class InactiveServiceProgramPolicyCoordinator : IServiceProgramPolicyCoordinator
{
    public bool PersistentEnforcementAvailable => false;
    public Task<ProgramRuleChangeResponse> ChangeAsync(ProgramRuleChangeRequest request, CancellationToken cancellationToken) =>
        throw new InvalidOperationException(QuietShieldServiceProtocol.NotActiveMessage);
    public Task RecoverInterruptedAsync(CancellationToken cancellationToken) { cancellationToken.ThrowIfCancellationRequested(); return Task.CompletedTask; }
}

public sealed class PersistentProgramPolicyCoordinator : IServiceProgramPolicyCoordinator, IDisposable
{
    private readonly SemaphoreSlim _gate = new(1, 1);
    private readonly ServiceActivationConfiguration _activation;
    private readonly PersistentServiceRuntime _runtime;
    private readonly PersistentFirewallTransactionStore _transactions;
    private readonly IPersistentFirewallBackend _backend;

    public PersistentProgramPolicyCoordinator(
        ServiceActivationConfiguration activation,
        PersistentServiceRuntime runtime,
        PersistentFirewallTransactionStore transactions,
        IPersistentFirewallBackend backend)
    {
        _activation = activation;
        _runtime = runtime;
        _transactions = transactions;
        _backend = backend;
    }

    public bool PersistentEnforcementAvailable => _backend.IsRealWindowsModifier;

    public async Task<ProgramRuleChangeResponse> ChangeAsync(ProgramRuleChangeRequest request, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(request);
        await _gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            ValidateRequest(request);
            var transactionId = Guid.NewGuid();
            var stableRuleId = ComputeStableRuleId(request.ProfileId, request.StableApplicationIdentity);
            var ruleName = "QuietShield.ProgramLock." + stableRuleId;
            var description = $"QuietShield Program Lock; schema=1; id={stableRuleId}; owner=QuietShield";
            var checkpoint = new PersistentTransactionCheckpoint(transactionId, ProgramLockTransactionState.PreflightPassed, DateTimeOffset.UtcNow, true,
                "Exact persistent Program Lock preflight passed.");
            await _runtime.UpdateTransactionAsync(checkpoint, cancellationToken).ConfigureAwait(false);
            var backup = await _backend.GetExactAsync(ruleName, cancellationToken).ConfigureAwait(false);
            var transaction = new PersistentFirewallTransaction(
                PersistentFirewallTransaction.CurrentSchemaVersion,
                QuietShieldServiceIdentity.ProductMarker,
                QuietShieldServiceIdentity.RehearsalPurpose,
                transactionId,
                request.ApprovedRehearsalId,
                DateTimeOffset.UtcNow,
                "BackupCreated",
                request.ProfileId,
                request.StableApplicationIdentity,
                Path.GetFullPath(request.ExecutablePath),
                request.ExecutableSha256.ToUpperInvariant(),
                request.Policy,
                stableRuleId,
                ruleName,
                description,
                backup,
                Enum.GetValues<SafetyExemptionKind>().Select(SafetyExemption.Create).ToArray(),
                string.Empty);
            transaction = transaction with { PayloadSha256 = transaction.ComputePayloadSha256() };
            await _transactions.SaveImmutableAsync(transaction, cancellationToken).ConfigureAwait(false);
            await _runtime.UpdateTransactionAsync(checkpoint with { State = ProgramLockTransactionState.BackupCreated, UpdatedAtUtc = DateTimeOffset.UtcNow, Detail = "Immutable exact-rule backup created and validated." }, cancellationToken).ConfigureAwait(false);
            var applyStarted = false;
            try
            {
                await _runtime.UpdateTransactionAsync(checkpoint with { State = ProgramLockTransactionState.ApplyStarted, UpdatedAtUtc = DateTimeOffset.UtcNow, Detail = "Exact approved rule application started." }, cancellationToken).ConfigureAwait(false);
                applyStarted = true;
                if (request.Policy == ProgramConnectionPolicy.Blocked) await _backend.ApplyBlockedAsync(transaction, cancellationToken).ConfigureAwait(false);
                else await _backend.ApplyAllowedOnAllAsync(transaction, cancellationToken).ConfigureAwait(false);
                var actual = await _backend.GetExactAsync(ruleName, cancellationToken).ConfigureAwait(false);
                if (request.Policy == ProgramConnectionPolicy.Blocked && !IsExactBlockedRule(transaction, actual)) throw new InvalidDataException("The exact Blocked rule verification failed.");
                if (request.Policy == ProgramConnectionPolicy.AllowedOnAll && actual is not null) throw new InvalidDataException("The exact QuietShield block rule remains after AllowedOnAll.");
                await _runtime.UpdateTransactionAsync(checkpoint with { State = ProgramLockTransactionState.VerificationPassed, UpdatedAtUtc = DateTimeOffset.UtcNow, Detail = "Exact rule verification passed." }, cancellationToken).ConfigureAwait(false);
                await _runtime.CommitPolicyAsync(request.ProfileId, new(request.StableApplicationIdentity, request.Policy, true), transaction.PayloadSha256, cancellationToken).ConfigureAwait(false);
                return new(transactionId, request.Policy, ruleName, "Committed", actual is not null,
                    transaction.SafetyExemptions.Select(static item => $"{item.Kind}: {item.VisibleReason}").ToArray());
            }
            catch
            {
                if (applyStarted)
                {
                    await _runtime.UpdateTransactionAsync(checkpoint with { State = ProgramLockTransactionState.RollbackStarted, UpdatedAtUtc = DateTimeOffset.UtcNow, Detail = "Verification failed; exact rollback started." }, CancellationToken.None).ConfigureAwait(false);
                    await _backend.RestoreAsync(transaction, CancellationToken.None).ConfigureAwait(false);
                    await _runtime.UpdateTransactionAsync(checkpoint with { State = ProgramLockTransactionState.Restored, UpdatedAtUtc = DateTimeOffset.UtcNow, RollbackEligible = false, Detail = "Exact original rule state restored." }, CancellationToken.None).ConfigureAwait(false);
                }
                throw;
            }
        }
        finally { _gate.Release(); }
    }

    public async Task RecoverInterruptedAsync(CancellationToken cancellationToken)
    {
        var checkpoint = _runtime.GetState().TransactionCheckpoint;
        if (!checkpoint.IsInterrupted || !checkpoint.TransactionId.HasValue) return;
        await _gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            var transaction = await _transactions.ReadValidatedAsync(checkpoint.TransactionId.Value, cancellationToken).ConfigureAwait(false);
            await _backend.RestoreAsync(transaction, cancellationToken).ConfigureAwait(false);
            await _runtime.UpdateTransactionAsync(checkpoint with { State = ProgramLockTransactionState.Restored, UpdatedAtUtc = DateTimeOffset.UtcNow, RollbackEligible = false, Detail = "Interrupted exact rule transaction restored before IPC readiness." }, cancellationToken).ConfigureAwait(false);
        }
        finally { _gate.Release(); }
    }

    private void ValidateRequest(ProgramRuleChangeRequest request)
    {
        var activationErrors = _activation.Validate(DateTimeOffset.UtcNow);
        if (activationErrors.Count != 0) throw new InvalidDataException(string.Join(" ", activationErrors));
        if (request.ApprovedRehearsalId != _activation.ApprovedRehearsalId) throw new UnauthorizedAccessException("The request is outside the approved rehearsal transaction.");
        if (request.Policy is not (ProgramConnectionPolicy.Blocked or ProgramConnectionPolicy.AllowedOnAll)) throw new NotSupportedException("Network-specific policies remain simulation-only.");
        if (string.IsNullOrWhiteSpace(request.ProfileId) || string.IsNullOrWhiteSpace(request.StableApplicationIdentity)) throw new InvalidDataException("An exact profile and stable application identity are required.");
        if (!request.StableApplicationIdentity.Equals("quietshield.connection-probe", StringComparison.Ordinal)) throw new UnauthorizedAccessException("Only QuietShield.ConnectionProbe is approved for the controlled rehearsal.");
        if (!Path.GetFullPath(request.ExecutablePath).Equals(Path.GetFullPath(_activation.ProbePath), StringComparison.OrdinalIgnoreCase)) throw new UnauthorizedAccessException("Only the approved dedicated connection probe may be changed.");
        using var stream = File.OpenRead(request.ExecutablePath);
        var actualHash = Convert.ToHexString(SHA256.HashData(stream));
        if (!actualHash.Equals(request.ExecutableSha256, StringComparison.OrdinalIgnoreCase) || !actualHash.Equals(_activation.ProbeSha256, StringComparison.OrdinalIgnoreCase))
            throw new InvalidDataException("The approved probe executable hash does not match.");
    }

    private static string ComputeStableRuleId(string profileId, string stableApplicationIdentity)
    {
        var canonical = string.Join("|", 1, profileId.Trim(), stableApplicationIdentity.Trim(), ProgramConnectionPolicy.Blocked,
            ProgramLockRuleDirection.Outbound, ProgramLockProtocolScope.Any, ProgramLockNetworkScope.All);
        return Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(canonical)))[..32].ToLowerInvariant();
    }

    private static bool IsExactBlockedRule(PersistentFirewallTransaction transaction, PersistentFirewallRuleSnapshot? actual) =>
        actual is not null && actual.OwnershipMarker == "QuietShield" && actual.SchemaVersion == 1 &&
        actual.Name.Equals(transaction.RuleName, StringComparison.Ordinal) && actual.Description.Equals(transaction.Description, StringComparison.Ordinal) &&
        Path.GetFullPath(actual.ProgramPath).Equals(Path.GetFullPath(transaction.ProgramPath), StringComparison.OrdinalIgnoreCase) && actual.Enabled &&
        actual.Direction.Equals("Outbound", StringComparison.OrdinalIgnoreCase) && actual.Action.Equals("Block", StringComparison.OrdinalIgnoreCase) &&
        actual.Profile.Equals("Any", StringComparison.OrdinalIgnoreCase) && actual.Protocol.Equals("Any", StringComparison.OrdinalIgnoreCase);

    public void Dispose()
    {
        _gate.Dispose();
        GC.SuppressFinalize(this);
    }
}

public sealed class InMemoryPersistentFirewallBackend : IPersistentFirewallBackend
{
    private readonly Dictionary<string, PersistentFirewallRuleSnapshot> _rules = new(StringComparer.Ordinal);
    public InMemoryPersistentFirewallBackend(IEnumerable<PersistentFirewallRuleSnapshot>? rules = null)
    {
        foreach (var rule in rules ?? Array.Empty<PersistentFirewallRuleSnapshot>()) _rules.Add(rule.Name, rule);
    }
    public bool IsRealWindowsModifier => false;
    public IReadOnlyCollection<PersistentFirewallRuleSnapshot> Rules => _rules.Values;
    public Task<PersistentFirewallRuleSnapshot?> GetExactAsync(string ruleName, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        _rules.TryGetValue(ruleName, out var rule);
        return Task.FromResult(rule);
    }
    public Task ApplyBlockedAsync(PersistentFirewallTransaction transaction, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        if (_rules.TryGetValue(transaction.RuleName, out var existing) && existing.OwnershipMarker != "QuietShield") throw new InvalidOperationException("A foreign exact-name rule collision was refused.");
        _rules[transaction.RuleName] = new("QuietShield", 1, transaction.RuleName, transaction.Description, transaction.ProgramPath, true, "Outbound", "Block", "Any", "Any", "Any", 0);
        return Task.CompletedTask;
    }
    public Task ApplyAllowedOnAllAsync(PersistentFirewallTransaction transaction, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        if (_rules.TryGetValue(transaction.RuleName, out var existing) && (existing.OwnershipMarker != "QuietShield" || !existing.ProgramPath.Equals(transaction.ProgramPath, StringComparison.OrdinalIgnoreCase)))
            throw new InvalidOperationException("Foreign or mismatched exact-name rule removal was refused.");
        _rules.Remove(transaction.RuleName);
        return Task.CompletedTask;
    }
    public Task RestoreAsync(PersistentFirewallTransaction transaction, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        if (transaction.BackupRule is null) _rules.Remove(transaction.RuleName);
        else _rules[transaction.RuleName] = transaction.BackupRule;
        return Task.CompletedTask;
    }
}
