namespace QuietShield.Core.ConnectionLock.Transactions;

public interface IProgramLockRuleEnumerator
{
    Task<IReadOnlyList<QuietShieldProgramRuleIdentity>> EnumerateAsync(CancellationToken cancellationToken);
}

public interface IProgramLockRuleCreator
{
    Task CreateAsync(QuietShieldProgramRuleIdentity rule, CancellationToken cancellationToken);
}

public interface IProgramLockRuleUpdater
{
    Task UpdateAsync(QuietShieldProgramRuleIdentity existing, QuietShieldProgramRuleIdentity replacement, CancellationToken cancellationToken);
}

public interface IProgramLockRuleRemover
{
    Task RemoveAsync(string stableRuleId, CancellationToken cancellationToken);
}

public interface IProgramLockRuleVerifier
{
    Task<bool> VerifyAsync(QuietShieldProgramRuleIdentity expected, CancellationToken cancellationToken);
}

public interface IProgramLockRollback
{
    Task RollbackAsync(ProgramLockBackup backup, CancellationToken cancellationToken);
}

public interface IProgramLockInterruptedTransactionRecovery
{
    Task RecoverInterruptedAsync(ProgramLockBackup backup, ProgramLockTransactionState state, CancellationToken cancellationToken);
}

public class InMemoryProgramLockRuleEnvironment :
    IProgramLockRuleEnumerator,
    IProgramLockRuleCreator,
    IProgramLockRuleUpdater,
    IProgramLockRuleRemover,
    IProgramLockRuleVerifier,
    IProgramLockRollback,
    IProgramLockInterruptedTransactionRecovery
{
    private readonly List<QuietShieldProgramRuleIdentity> _rules;
    private readonly List<string> _foreignRuleNames;

    public InMemoryProgramLockRuleEnvironment(
        IEnumerable<QuietShieldProgramRuleIdentity>? rules = null,
        IEnumerable<string>? foreignRuleNames = null)
    {
        _rules = (rules ?? Array.Empty<QuietShieldProgramRuleIdentity>()).ToList();
        _foreignRuleNames = (foreignRuleNames ?? Array.Empty<string>()).ToList();
    }

    public IReadOnlyList<string> ForeignRuleNames => _foreignRuleNames.AsReadOnly();

    public Task<IReadOnlyList<QuietShieldProgramRuleIdentity>> EnumerateAsync(CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        return Task.FromResult<IReadOnlyList<QuietShieldProgramRuleIdentity>>(_rules.ToArray());
    }

    public Task CreateAsync(QuietShieldProgramRuleIdentity rule, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        EnsureOwned(rule);
        if (_foreignRuleNames.Contains(rule.RuleName, StringComparer.OrdinalIgnoreCase)) throw new InvalidOperationException("A foreign rule name collision is present.");
        if (_rules.Any(existing => existing.StableRuleId.Equals(rule.StableRuleId, StringComparison.Ordinal))) throw new InvalidOperationException("A duplicate QuietShield stable rule ID is prohibited.");
        _rules.Add(rule);
        return Task.CompletedTask;
    }

    public Task UpdateAsync(QuietShieldProgramRuleIdentity existing, QuietShieldProgramRuleIdentity replacement, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        EnsureOwned(existing);
        EnsureOwned(replacement);
        var index = _rules.FindIndex(rule => rule.StableRuleId.Equals(existing.StableRuleId, StringComparison.Ordinal));
        if (index < 0) throw new KeyNotFoundException("The exact existing QuietShield rule was not found.");
        _rules[index] = replacement;
        return Task.CompletedTask;
    }

    public Task RemoveAsync(string stableRuleId, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        var matching = _rules.Where(rule => rule.StableRuleId.Equals(stableRuleId, StringComparison.Ordinal)).ToArray();
        if (matching.Length > 1) throw new InvalidOperationException("Removal is ambiguous because duplicate owned rule IDs exist.");
        if (matching.Length == 1) _rules.Remove(matching[0]);
        return Task.CompletedTask;
    }

    public async Task<bool> VerifyAsync(QuietShieldProgramRuleIdentity expected, CancellationToken cancellationToken)
    {
        var rules = await EnumerateAsync(cancellationToken).ConfigureAwait(false);
        return rules.Count(rule => rule.StableRuleId.Equals(expected.StableRuleId, StringComparison.Ordinal) &&
                                   rule.ComputePayloadSha256().Equals(expected.ComputePayloadSha256(), StringComparison.Ordinal)) == 1;
    }

    public async Task RollbackAsync(ProgramLockBackup backup, CancellationToken cancellationToken)
    {
        var validation = ProgramLockBackupValidator.Validate(backup);
        if (!validation.IsValid) throw new InvalidDataException(string.Join(" ", validation.Errors));
        _rules.Clear();
        foreach (var entry in backup.QuietShieldOwnedRules.OrderBy(static item => item.OriginalOrder))
            await CreateAsync(entry.Rule, cancellationToken).ConfigureAwait(false);
    }

    public Task RecoverInterruptedAsync(ProgramLockBackup backup, ProgramLockTransactionState state, CancellationToken cancellationToken)
    {
        if (state is not (ProgramLockTransactionState.ApplyStarted or ProgramLockTransactionState.RulesApplied or
            ProgramLockTransactionState.VerificationStarted or ProgramLockTransactionState.VerificationPassed or
            ProgramLockTransactionState.InterruptedRecoveryRequired))
            throw new InvalidOperationException("The transaction state does not require interrupted recovery.");
        return RollbackAsync(backup, cancellationToken);
    }

    public async Task ApplyPlanAsync(ProgramLockRulePlan plan, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(plan);
        if (!plan.IsValid) throw new InvalidOperationException("An invalid plan cannot be simulated.");
        foreach (var operation in plan.Operations)
        {
            switch (operation.Operation)
            {
                case ProgramLockRuleOperationKind.Add:
                    await CreateAsync(operation.ProposedRule!, cancellationToken).ConfigureAwait(false);
                    break;
                case ProgramLockRuleOperationKind.Replace:
                    await UpdateAsync(operation.ExistingRule!, operation.ProposedRule!, cancellationToken).ConfigureAwait(false);
                    break;
                case ProgramLockRuleOperationKind.Remove:
                    await RemoveAsync(operation.ExistingRule!.StableRuleId, cancellationToken).ConfigureAwait(false);
                    break;
                case ProgramLockRuleOperationKind.Preserve:
                case ProgramLockRuleOperationKind.NoChange:
                    break;
                default:
                    throw new InvalidOperationException("Unsupported operations cannot be simulated as applied.");
            }
        }
    }

    private static void EnsureOwned(QuietShieldProgramRuleIdentity rule)
    {
        var validation = rule.Validate();
        if (!validation.IsValid) throw new InvalidDataException(string.Join(" ", validation.Errors));
    }
}

public sealed class FixtureProgramLockRuleEnvironment : InMemoryProgramLockRuleEnvironment
{
    public FixtureProgramLockRuleEnvironment(
        IEnumerable<QuietShieldProgramRuleIdentity> rules,
        IEnumerable<string>? foreignRuleNames = null) : base(rules, foreignRuleNames)
    {
    }
}
