namespace QuietShield.Core.ConnectionLock.Rehearsal;

public sealed class ProgramLockFirewallRehearsalStateMachine
{
    private static readonly Dictionary<ProgramLockFirewallRehearsalState, ProgramLockFirewallRehearsalState[]> Transitions =
        new Dictionary<ProgramLockFirewallRehearsalState, ProgramLockFirewallRehearsalState[]>
        {
            [ProgramLockFirewallRehearsalState.Prepared] = new[] { ProgramLockFirewallRehearsalState.EndpointVerified },
            [ProgramLockFirewallRehearsalState.EndpointVerified] = new[] { ProgramLockFirewallRehearsalState.BackupCreated },
            [ProgramLockFirewallRehearsalState.BackupCreated] = new[] { ProgramLockFirewallRehearsalState.WatchdogStarted },
            [ProgramLockFirewallRehearsalState.WatchdogStarted] = new[] { ProgramLockFirewallRehearsalState.RuleCreated },
            [ProgramLockFirewallRehearsalState.RuleCreated] = new[] { ProgramLockFirewallRehearsalState.RuleVerified, ProgramLockFirewallRehearsalState.RollbackStarted },
            [ProgramLockFirewallRehearsalState.RuleVerified] = new[] { ProgramLockFirewallRehearsalState.BlockVerified, ProgramLockFirewallRehearsalState.RollbackStarted },
            [ProgramLockFirewallRehearsalState.BlockVerified] = new[] { ProgramLockFirewallRehearsalState.RehearsalActive, ProgramLockFirewallRehearsalState.RollbackStarted },
            [ProgramLockFirewallRehearsalState.RehearsalActive] = new[] { ProgramLockFirewallRehearsalState.RollbackStarted },
            [ProgramLockFirewallRehearsalState.RollbackStarted] = new[] { ProgramLockFirewallRehearsalState.RuleRemoved },
            [ProgramLockFirewallRehearsalState.RuleRemoved] = new[] { ProgramLockFirewallRehearsalState.ConnectivityRestored },
            [ProgramLockFirewallRehearsalState.ConnectivityRestored] = new[] { ProgramLockFirewallRehearsalState.Completed },
            [ProgramLockFirewallRehearsalState.Completed] = Array.Empty<ProgramLockFirewallRehearsalState>()
        };

    public ProgramLockFirewallRehearsalStateMachine(ProgramLockFirewallRehearsalState initial) => State = initial;
    public ProgramLockFirewallRehearsalState State { get; private set; }
    public bool RuleMayExist => State is >= ProgramLockFirewallRehearsalState.RuleCreated and < ProgramLockFirewallRehearsalState.RuleRemoved;

    public void TransitionTo(ProgramLockFirewallRehearsalState next)
    {
        if (!Transitions[State].Contains(next)) throw new InvalidOperationException($"Transition {State} -> {next} is not permitted.");
        State = next;
    }

    public void Fail()
    {
        if (RuleMayExist && State != ProgramLockFirewallRehearsalState.RollbackStarted)
            TransitionTo(ProgramLockFirewallRehearsalState.RollbackStarted);
        else if (!RuleMayExist)
            throw new InvalidOperationException("A pre-rule failure must stop without a Firewall change.");
    }
}
