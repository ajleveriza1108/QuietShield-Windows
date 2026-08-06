using System.Security.Cryptography;
using System.Text;

namespace QuietShield.Core.ConnectionLock.Transactions;

public enum ProgramLockTransactionState
{
    Draft,
    PreflightPassed,
    BackupCreated,
    PlanValidated,
    ApplyStarted,
    RulesApplied,
    VerificationStarted,
    VerificationPassed,
    Committed,
    RollbackStarted,
    Restored,
    FailedSafely,
    InterruptedRecoveryRequired
}

public sealed record ProgramLockTransactionHistoryEntry(
    int Sequence,
    Guid TransactionId,
    ProgramLockTransactionState? PreviousState,
    ProgramLockTransactionState State,
    DateTimeOffset OccurredAtUtc,
    string Reason,
    string PreviousEntrySha256,
    string EntrySha256);

public sealed class ProgramLockTransactionStateMachine
{
    private static readonly Dictionary<ProgramLockTransactionState, HashSet<ProgramLockTransactionState>> Transitions =
        new()
        {
            [ProgramLockTransactionState.Draft] = Set(ProgramLockTransactionState.PreflightPassed, ProgramLockTransactionState.FailedSafely),
            [ProgramLockTransactionState.PreflightPassed] = Set(ProgramLockTransactionState.BackupCreated, ProgramLockTransactionState.FailedSafely),
            [ProgramLockTransactionState.BackupCreated] = Set(ProgramLockTransactionState.PlanValidated, ProgramLockTransactionState.FailedSafely),
            [ProgramLockTransactionState.PlanValidated] = Set(ProgramLockTransactionState.ApplyStarted, ProgramLockTransactionState.FailedSafely),
            [ProgramLockTransactionState.ApplyStarted] = Set(ProgramLockTransactionState.RulesApplied, ProgramLockTransactionState.RollbackStarted, ProgramLockTransactionState.InterruptedRecoveryRequired),
            [ProgramLockTransactionState.RulesApplied] = Set(ProgramLockTransactionState.VerificationStarted, ProgramLockTransactionState.RollbackStarted, ProgramLockTransactionState.InterruptedRecoveryRequired),
            [ProgramLockTransactionState.VerificationStarted] = Set(ProgramLockTransactionState.VerificationPassed, ProgramLockTransactionState.RollbackStarted, ProgramLockTransactionState.InterruptedRecoveryRequired),
            [ProgramLockTransactionState.VerificationPassed] = Set(ProgramLockTransactionState.Committed, ProgramLockTransactionState.RollbackStarted, ProgramLockTransactionState.InterruptedRecoveryRequired),
            [ProgramLockTransactionState.RollbackStarted] = Set(ProgramLockTransactionState.Restored, ProgramLockTransactionState.InterruptedRecoveryRequired),
            [ProgramLockTransactionState.InterruptedRecoveryRequired] = Set(ProgramLockTransactionState.RollbackStarted),
            [ProgramLockTransactionState.Committed] = Set(ProgramLockTransactionState.RollbackStarted),
            [ProgramLockTransactionState.Restored] = new HashSet<ProgramLockTransactionState>(),
            [ProgramLockTransactionState.FailedSafely] = new HashSet<ProgramLockTransactionState>()
        };

    private readonly List<ProgramLockTransactionHistoryEntry> _history = new();

    public ProgramLockTransactionStateMachine(Guid transactionId, DateTimeOffset createdAtUtc)
    {
        if (transactionId == Guid.Empty) throw new ArgumentException("A transaction ID is required.", nameof(transactionId));
        TransactionId = transactionId;
        State = ProgramLockTransactionState.Draft;
        Append(null, State, createdAtUtc, "Transaction draft created for simulation only.");
    }

    public Guid TransactionId { get; }
    public ProgramLockTransactionState State { get; private set; }
    public IReadOnlyList<ProgramLockTransactionHistoryEntry> History => _history.AsReadOnly();
    public bool ApplyHasStarted => State is ProgramLockTransactionState.ApplyStarted or ProgramLockTransactionState.RulesApplied or
        ProgramLockTransactionState.VerificationStarted or ProgramLockTransactionState.VerificationPassed or ProgramLockTransactionState.Committed or
        ProgramLockTransactionState.RollbackStarted or ProgramLockTransactionState.Restored or ProgramLockTransactionState.InterruptedRecoveryRequired;
    public bool RequiresRollback => State is ProgramLockTransactionState.ApplyStarted or ProgramLockTransactionState.RulesApplied or
        ProgramLockTransactionState.VerificationStarted or ProgramLockTransactionState.VerificationPassed or ProgramLockTransactionState.Committed or
        ProgramLockTransactionState.InterruptedRecoveryRequired;

    public void TransitionTo(ProgramLockTransactionState next, DateTimeOffset occurredAtUtc, string reason)
    {
        if (!Transitions[State].Contains(next)) throw new InvalidOperationException($"Transition {State} -> {next} is not permitted.");
        var previous = State;
        State = next;
        Append(previous, next, occurredAtUtc, reason);
    }

    public void Fail(DateTimeOffset occurredAtUtc, string reason, bool interrupted)
    {
        if (ApplyHasStarted)
        {
            var target = interrupted ? ProgramLockTransactionState.InterruptedRecoveryRequired : ProgramLockTransactionState.RollbackStarted;
            TransitionTo(target, occurredAtUtc, reason);
            return;
        }
        TransitionTo(ProgramLockTransactionState.FailedSafely, occurredAtUtc, reason);
    }

    private void Append(ProgramLockTransactionState? previous, ProgramLockTransactionState state, DateTimeOffset time, string reason)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(reason);
        var sequence = _history.Count;
        var previousHash = sequence == 0 ? new string('0', 64) : _history[^1].EntrySha256;
        var canonical = string.Join("|", sequence, TransactionId.ToString("D"), previous?.ToString() ?? string.Empty, state, time.ToUniversalTime().ToString("O"), reason, previousHash);
        var hash = Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(canonical)));
        _history.Add(new(sequence, TransactionId, previous, state, time.ToUniversalTime(), reason, previousHash, hash));
    }

    private static HashSet<ProgramLockTransactionState> Set(params ProgramLockTransactionState[] states) => states.ToHashSet();
}
