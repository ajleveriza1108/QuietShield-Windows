using System.Collections.ObjectModel;
using System.IO;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Windows.Input;
using QuietShield.Core.ConnectionLock;
using QuietShield.Core.ConnectionLock.Transactions;
using QuietShield.Core.Protection;

namespace QuietShield.App.ViewModels;

public sealed record ProgramLockPlanViewerItem(
    string Application,
    string CurrentSimulatedPolicy,
    string ProposedOperation,
    string Enforceability,
    string Reason,
    string RequiredPrivilege,
    string RollbackAction,
    string FutureRuleId);

public sealed partial class MainViewModel
{
    private static readonly Guid PreviewTransactionId = Guid.Parse("80000000-0000-0000-0000-000000000008");
    private static readonly JsonSerializerOptions PlanExportOptions = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        WriteIndented = true,
        Converters = { new JsonStringEnumConverter() }
    };

    private ProgramLockRulePlan? _currentProgramLockPlan;
    private string _transactionPreviewStatus = "Select an application to generate a read-only transaction plan.";

    public ObservableCollection<ProgramLockPlanViewerItem> ProgramLockPlanOperations { get; } = new();
    public ICommand PreviewEnforcementPlanCommand { get; private set; } = null!;
    public ICommand ExportEnforcementPlanCommand { get; private set; } = null!;
    public string TransactionReadiness { get; } = "Draft / dry-run ready; no modifying Windows implementation is registered.";
    public string SelectedTransactionProfile => _selectedConnectionProfile?.Name ?? "No profile selected";
    public int EnforceablePolicyCount { get; } = Enum.GetValues<ProgramConnectionPolicy>()
        .Count(static policy => PolicyEnforceabilityClassifier.Classify(policy).Support == PolicyEnforcementSupport.WindowsFirewallStatic);
    public int UnsupportedPolicyCount { get; } = Enum.GetValues<ProgramConnectionPolicy>()
        .Count(static policy => PolicyEnforceabilityClassifier.Classify(policy).Support != PolicyEnforcementSupport.WindowsFirewallStatic);
    public int ProposedRuleOperationCount => ProgramLockPlanOperations.Count;
    public string BackupReadiness { get; } = "Ready: immutable schema, ownership, rule-order, and SHA-256 validation modeled.";
    public string RollbackReadiness { get; } = "Ready: normal, partial, interrupted, stale, and profile-switch rollback simulations modeled.";
    public string EmergencyRecoveryReadiness { get; } = "Ready for validated QuietShield-owned data only; Phase 8 cannot modify Windows.";
    public string TransactionPreviewStatus { get => _transactionPreviewStatus; private set => SetField(ref _transactionPreviewStatus, value); }

    private void InitializeProgramLockTransactions()
    {
        PreviewEnforcementPlanCommand = new AsyncRelayCommand(PreviewEnforcementPlanAsync);
        ExportEnforcementPlanCommand = new AsyncRelayCommand(ExportEnforcementPlanAsync, () => _currentProgramLockPlan is not null);
    }

    private Task PreviewEnforcementPlanAsync()
    {
        RefreshProgramLockTransactionPlan();
        return Task.CompletedTask;
    }

    private void RefreshProgramLockTransactionPlan()
    {
        ProgramLockPlanOperations.Clear();
        _currentProgramLockPlan = null;
        if (SelectedApplication is null || _selectedConnectionProfile is null)
        {
            TransactionPreviewStatus = "Select an application to generate a read-only transaction plan.";
            RaiseProgramLockTransactionProperties();
            return;
        }

        var identity = CreateProgramIdentity(SelectedApplication.Application);
        var validation = identity.Validate();
        if (!validation.IsValid)
        {
            ProgramLockPlanOperations.Add(new(
                SelectedApplication.DisplayName,
                SelectedPolicy.ToString(),
                ProgramLockRuleOperationKind.Unsupported.ToString(),
                PolicyEnforcementSupport.Unsupported.ToString(),
                string.Join(" ", validation.Errors),
                "No privilege is used by this dry-run operation.",
                ProgramLockRollbackCounterpart.None.ToString(),
                "[unavailable]"));
            TransactionPreviewStatus = "Plan safely refused because the exact application identity is unavailable.";
            RaiseProgramLockTransactionProperties();
            return;
        }

        var desired = new[] { new ConnectionLockProgramRule(identity, SelectedPolicy) };
        _currentProgramLockPlan = ProgramLockRulePlanGenerator.Generate(
            PreviewTransactionId,
            _selectedConnectionProfile,
            desired,
            Array.Empty<QuietShieldProgramRuleIdentity>());
        foreach (var operation in _currentProgramLockPlan.Operations)
        {
            ProgramLockPlanOperations.Add(new(
                SelectedApplication.DisplayName,
                SelectedPolicy.ToString(),
                operation.Operation.ToString(),
                operation.Enforceability.ToString(),
                operation.Reason,
                operation.RequiredPrivilege,
                operation.RollbackCounterpart.ToString(),
                operation.FutureRuleId));
        }
        TransactionPreviewStatus = $"Preview generated: {_currentProgramLockPlan.Operations.Count} operation(s); executable: {_currentProgramLockPlan.CanExecute}; hash {_currentProgramLockPlan.PlanSha256}.";
        RaiseProgramLockTransactionProperties();
    }

    private async Task ExportEnforcementPlanAsync()
    {
        var directory = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments), "QuietShield Plans");
        var path = Path.Combine(directory, $"program-lock-plan-{DateTimeOffset.Now:yyyyMMdd-HHmmss}.json");
        await ExportEnforcementPlanForValidationAsync(path, CancellationToken.None).ConfigureAwait(true);
        TransactionPreviewStatus = $"Read-only enforcement plan exported to {path}";
    }

    public async Task ExportEnforcementPlanForValidationAsync(string destinationPath, CancellationToken cancellationToken)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(destinationPath);
        if (_currentProgramLockPlan is null) RefreshProgramLockTransactionPlan();
        if (_currentProgramLockPlan is null) throw new InvalidOperationException("A validated application identity is required before plan export.");
        var resolved = Path.GetFullPath(destinationPath);
        var directory = Path.GetDirectoryName(resolved) ?? throw new InvalidOperationException("The export path has no directory.");
        Directory.CreateDirectory(directory);
        await File.WriteAllTextAsync(resolved, JsonSerializer.Serialize(_currentProgramLockPlan, PlanExportOptions), cancellationToken).ConfigureAwait(true);
    }

    private void RaiseProgramLockTransactionProperties()
    {
        OnPropertyChanged(nameof(SelectedTransactionProfile));
        OnPropertyChanged(nameof(ProposedRuleOperationCount));
        if (ExportEnforcementPlanCommand is AsyncRelayCommand export) export.RaiseCanExecuteChanged();
    }
}
