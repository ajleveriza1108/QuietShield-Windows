namespace QuietShield.Core.ConnectionLock.Rehearsal;

public enum ProgramLockWatchdogTrigger
{
    None,
    DeadlineExpired,
    HeartbeatLost,
    ParentProcessLost,
    VerificationFailed,
    ProbeExitedUnexpectedly,
    RollbackRequested
}

public sealed record ProgramLockWatchdogObservation(
    DateTimeOffset NowUtc,
    DateTimeOffset DeadlineUtc,
    bool ParentProcessAlive,
    bool HeartbeatStarted,
    DateTimeOffset? LastHeartbeatUtc,
    TimeSpan HeartbeatTimeout,
    bool VerificationFailed,
    bool ProbeExitedUnexpectedly,
    bool RollbackRequested,
    bool RuleCreated,
    bool RuleAbsent);

public sealed record ProgramLockWatchdogDecision(bool CleanupRequired, bool Stop, ProgramLockWatchdogTrigger Trigger);

public static class ProgramLockFirewallWatchdogEvaluator
{
    public static ProgramLockWatchdogDecision Evaluate(ProgramLockWatchdogObservation observation)
    {
        if (observation.RuleAbsent) return new(false, true, ProgramLockWatchdogTrigger.None);
        if (!observation.RuleCreated) return new(false, false, ProgramLockWatchdogTrigger.None);
        if (observation.RollbackRequested) return new(true, false, ProgramLockWatchdogTrigger.RollbackRequested);
        if (observation.VerificationFailed) return new(true, false, ProgramLockWatchdogTrigger.VerificationFailed);
        if (observation.ProbeExitedUnexpectedly) return new(true, false, ProgramLockWatchdogTrigger.ProbeExitedUnexpectedly);
        if (!observation.ParentProcessAlive) return new(true, false, ProgramLockWatchdogTrigger.ParentProcessLost);
        if (observation.NowUtc >= observation.DeadlineUtc) return new(true, false, ProgramLockWatchdogTrigger.DeadlineExpired);
        if (observation.HeartbeatStarted && (!observation.LastHeartbeatUtc.HasValue ||
            observation.NowUtc - observation.LastHeartbeatUtc.Value > observation.HeartbeatTimeout))
            return new(true, false, ProgramLockWatchdogTrigger.HeartbeatLost);
        return new(false, false, ProgramLockWatchdogTrigger.None);
    }
}

public interface IExactProgramLockRehearsalRuleStore
{
    bool ContainsExact(string ruleName);
    bool RemoveExact(string ruleName);
    IReadOnlyCollection<string> RuleNames { get; }
}

public sealed class InMemoryExactProgramLockRehearsalRuleStore : IExactProgramLockRehearsalRuleStore
{
    private readonly HashSet<string> _rules;
    public InMemoryExactProgramLockRehearsalRuleStore(IEnumerable<string> ruleNames) => _rules = new(ruleNames, StringComparer.Ordinal);
    public IReadOnlyCollection<string> RuleNames => _rules;
    public bool ContainsExact(string ruleName) => _rules.Contains(ruleName);
    public bool RemoveExact(string ruleName) => _rules.Remove(ruleName);
}

public static class ProgramLockFirewallRehearsalCleanup
{
    public static bool RemoveExactValidatedRule(
        ProgramLockFirewallRehearsalTransaction transaction,
        IExactProgramLockRehearsalRuleStore store)
    {
        ArgumentNullException.ThrowIfNull(transaction);
        ArgumentNullException.ThrowIfNull(store);
        var validation = transaction.Validate(allowCompleted: false);
        if (!validation.IsValid) throw new InvalidDataException(string.Join(" ", validation.Errors));
        return store.RemoveExact(transaction.ProposedRule.RuleName);
    }

    public static void RefuseConcurrent(IEnumerable<ProgramLockFirewallRehearsalTransaction> transactions)
    {
        if (transactions.Any(static item => !item.Completed && item.State != ProgramLockFirewallRehearsalState.Completed))
            throw new InvalidOperationException("Another Program Lock Firewall rehearsal is active.");
    }
}
