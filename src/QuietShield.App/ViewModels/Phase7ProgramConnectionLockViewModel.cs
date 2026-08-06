using System.Collections.ObjectModel;
using System.IO;
using QuietShield.Core.ConnectionLock;
using QuietShield.Core.Protection;
using QuietShield.Core.Simulation;
using QuietShield.Windows.Integration;
using QuietShield.Windows.Planning;

namespace QuietShield.App.ViewModels;

public sealed record ScheduleListItem(string Name, string Days, string TimeRange, string TimeZone, string Policy, string ConflictRule);
public sealed record CompatibilityListItem(string Kind, string Target, string Relaxation, string Expiration);
public sealed record SafetyExemptionListItem(string Name, string Reason);

public sealed partial class MainViewModel
{
    private IProfileSelectionStore _profileSelectionStore = null!;
    private ProtectionProfileCatalog _connectionProfileCatalog = null!;
    private ConnectionLockProfile _selectedConnectionProfile = null!;
    private string _selectedTemporaryAllowance = "None";
    private string _selectedCompatibilityOption = "None";
    private bool _isParentProtectedSimulation;
    private string _identitySummary = "Select an application to inspect its stable identity.";
    private string _decisionEvidence = "No decision has been evaluated.";
    private string _plannerSummary = "No future enforcement plan has been generated.";
    private string _profilePersistenceStatus = "Selected profile persistence is ready.";

    public ObservableCollection<ConnectionLockProfile> ConnectionProfiles { get; } = new();
    public ObservableCollection<ScheduleListItem> ConnectionSchedules { get; } = new();
    public ObservableCollection<CompatibilityListItem> CompatibilityExclusions { get; } = new();
    public ObservableCollection<SafetyExemptionListItem> SafetyExemptions { get; } = new();
    public IReadOnlyList<string> TemporaryAllowanceOptions { get; } = new[] { "None", "Until program closes", "5 minutes", "15 minutes", "30 minutes", "60 minutes", "Custom expiration" };
    public IReadOnlyList<string> CompatibilityOptions { get; } = new[] { "None", "Selected program", "Exact domain", "15-minute bypass" };

    public ConnectionLockProfile SelectedConnectionProfile
    {
        get => _selectedConnectionProfile;
        set
        {
            if (value is null || Equals(_selectedConnectionProfile, value)) return;
            _selectedConnectionProfile = value;
            OnPropertyChanged();
            _connectionProfileCatalog.Select(value.Id);
            try
            {
                _profileSelectionStore.SaveSelectedProfileId(value.Id);
                ProfilePersistenceStatus = $"Selected profile '{value.Name}' persisted in privacy-safe local JSON.";
            }
            catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
            {
                ProfilePersistenceStatus = $"Selected profile is active for this session; persistence was unavailable: {exception.Message}";
            }
            UpdateProgramConnectionLockSimulation();
        }
    }

    public string SelectedTemporaryAllowance
    {
        get => _selectedTemporaryAllowance;
        set { if (SetField(ref _selectedTemporaryAllowance, value)) UpdateProgramConnectionLockSimulation(); }
    }

    public string SelectedCompatibilityOption
    {
        get => _selectedCompatibilityOption;
        set { if (SetField(ref _selectedCompatibilityOption, value)) UpdateProgramConnectionLockSimulation(); }
    }

    public bool IsParentProtectedSimulation
    {
        get => _isParentProtectedSimulation;
        set { if (SetField(ref _isParentProtectedSimulation, value)) UpdateProgramConnectionLockSimulation(); }
    }

    public string IdentitySummary { get => _identitySummary; private set => SetField(ref _identitySummary, value); }
    public string DecisionEvidence { get => _decisionEvidence; private set => SetField(ref _decisionEvidence, value); }
    public string PlannerSummary { get => _plannerSummary; private set => SetField(ref _plannerSummary, value); }
    public string ProfilePersistenceStatus { get => _profilePersistenceStatus; private set => SetField(ref _profilePersistenceStatus, value); }
    public string ProfileLimitSummary => $"{ConnectionProfiles.Count(static profile => !profile.IsFixed)} of {ProtectionProfileCatalog.MaximumEditableProfiles} editable profiles; Block All is fixed.";
    public string ProfileJsonSummary => $"Import/export schema 1 stores {ConnectionProfiles.Count} profile definitions, stable inventory IDs, policies, and selection only; executable paths are excluded.";
    public string DecisionPrecedenceSummary => $"{SelectedConnectionProfile.Name}: emergency recovery > required QuietShield component > parent protection > temporary allowance > Compatibility Guard > schedule > program rule > profile default > safe fallback.";

    private void InitializeProgramConnectionLock(IProfileSelectionStore profileSelectionStore)
    {
        _profileSelectionStore = profileSelectionStore;
        var editableProfiles = new[]
        {
            new ConnectionLockProfile("standard", "Standard", "Balanced simulation baseline for everyday applications.", ProgramConnectionPolicy.AllowedOnAll, Array.Empty<ConnectionLockProgramRule>(), false),
            new ConnectionLockProfile("focus", "Study", "Restrictive study simulation with unmetered connectivity by default.", ProgramConnectionPolicy.UnmeteredOnly, Array.Empty<ConnectionLockProgramRule>(), false),
            new ConnectionLockProfile("travel", "Travel", "Wi-Fi-only simulation for travel scenarios.", ProgramConnectionPolicy.WiFiOnly, Array.Empty<ConnectionLockProgramRule>(), false)
        };
        var selectedId = profileSelectionStore.LoadSelectedProfileId() ?? "standard";
        _connectionProfileCatalog = new ProtectionProfileCatalog(editableProfiles, selectedId);
        foreach (var profile in _connectionProfileCatalog.Profiles) ConnectionProfiles.Add(profile);
        _selectedConnectionProfile = _connectionProfileCatalog.SelectedProfile;

        var zone = TimeZoneInfo.Local.Id;
        var schedules = new[]
        {
            ConnectionPolicySchedule.CreatePreset(ConnectionSchedulePreset.Study, zone, "preset.study", ProgramConnectionPolicy.UnmeteredOnly),
            ConnectionPolicySchedule.CreatePreset(ConnectionSchedulePreset.Work, zone, "preset.work", ProgramConnectionPolicy.AllowedOnAll),
            ConnectionPolicySchedule.CreatePreset(ConnectionSchedulePreset.Bedtime, zone, "preset.bedtime", ProgramConnectionPolicy.Blocked),
            new ConnectionPolicySchedule("custom.weekend", "Custom weekend", new HashSet<DayOfWeek> { DayOfWeek.Saturday, DayOfWeek.Sunday }, new TimeOnly(10, 0), new TimeOnly(12, 0), zone, ProgramConnectionPolicy.WiFiOnly, ConnectionSchedulePreset.Custom, 100, false)
        };
        foreach (var schedule in schedules)
        {
            ConnectionSchedules.Add(new ScheduleListItem(
                schedule.Name,
                string.Join(", ", schedule.Days.Order()),
                $"{schedule.Start:HH:mm}-{schedule.End:HH:mm}{(schedule.CrossesMidnight ? " (overnight)" : string.Empty)}",
                schedule.TimeZoneId,
                schedule.Policy.ToString(),
                $"Priority {schedule.Priority}; ties use restrictive policy then stable ID"));
        }

        CompatibilityExclusions.Add(new CompatibilityListItem("Program", "Selected stable application ID", "Allow only the selected program's simulated connection", "Until removed"));
        CompatibilityExclusions.Add(new CompatibilityListItem("Domain", "Exact normalized domain", "Relax only the named domain for the selected program", "Until removed"));
        CompatibilityExclusions.Add(new CompatibilityListItem("Temporary bypass", "Selected stable application ID", "Allow only the selected program for 15 minutes", "Automatic"));
        foreach (var kind in Enum.GetValues<SafetyExemptionKind>())
        {
            var exemption = SafetyExemption.Create(kind);
            SafetyExemptions.Add(new SafetyExemptionListItem(kind.ToString(), exemption.VisibleReason));
        }
    }

    private void UpdateProgramConnectionLockSimulation()
    {
        if (SelectedApplication is null || _selectedConnectionProfile is null)
        {
            SimulationDecision = "Select an application to simulate a policy.";
            SimulationReason = SimulationBanner;
            IdentitySummary = "No exact program identity is selected.";
            DecisionEvidence = "No decision has been evaluated.";
            PlannerSummary = "No future enforcement plan has been generated.";
            return;
        }

        var identity = CreateProgramIdentity(SelectedApplication.Application);
        var rule = _selectedConnectionProfile.IsFixed ? null : new ConnectionLockProgramRule(identity, SelectedPolicy);
        var now = DateTimeOffset.UtcNow;
        var allowance = CreateTemporaryAllowance(now);
        var compatibility = CreateCompatibilityExclusion(now, identity);
        var input = new ConnectionDecisionInput(
            identity,
            _selectedConnectionProfile,
            SelectedConnectionType,
            now,
            rule,
            allowance,
            IsProgramRunning: allowance?.Kind == TemporaryAllowanceKind.UntilProgramCloses,
            compatibility,
            Schedule: null,
            SafetyExemption: null,
            IsParentProtected: IsParentProtectedSimulation);
        var result = ConnectionPolicyDecisionEngine.Evaluate(input);
        SimulationDecision = $"{result.Decision} — {result.MatchedRule}";
        SimulationReason = result.Reason;
        IdentitySummary = $"{identity.Kind}; {identity.StableId}; path/package status: {identity.PathStatus}; system component: {identity.IsSystemComponent}; evidence: {identity.IdentityEvidence}.";
        DecisionEvidence = $"Profile: {result.ActiveProfile}; connection: {result.ConnectionType}; schedule: {result.ScheduleResult}; compatibility: {result.CompatibilityResult}; exemption: {result.SafetyExemptionResult}.";

        var plannedRule = rule ?? new ConnectionLockProgramRule(identity, _selectedConnectionProfile.DefaultPolicy);
        var plan = new WindowsProgramEnforcementPlanner().Plan(plannedRule);
        PlannerSummary = $"{plan.Strategy}; target: {plan.Target}; privilege: {plan.RequiredPrivilege} Rollback steps: {plan.RollbackSteps.Count}. Executable: {plan.CanExecute}. {plan.UnsupportedOrAmbiguousReason}".Trim();
    }

    private ProgramTemporaryAllowance? CreateTemporaryAllowance(DateTimeOffset now) => SelectedTemporaryAllowance switch
    {
        "Until program closes" => ProgramTemporaryAllowance.CreateTimed(SelectedApplication!.Id, TemporaryAllowanceKind.UntilProgramCloses, now, SelectedPolicy),
        "5 minutes" => ProgramTemporaryAllowance.CreateTimed(SelectedApplication!.Id, TemporaryAllowanceKind.FiveMinutes, now, SelectedPolicy),
        "15 minutes" => ProgramTemporaryAllowance.CreateTimed(SelectedApplication!.Id, TemporaryAllowanceKind.FifteenMinutes, now, SelectedPolicy),
        "30 minutes" => ProgramTemporaryAllowance.CreateTimed(SelectedApplication!.Id, TemporaryAllowanceKind.ThirtyMinutes, now, SelectedPolicy),
        "60 minutes" => ProgramTemporaryAllowance.CreateTimed(SelectedApplication!.Id, TemporaryAllowanceKind.SixtyMinutes, now, SelectedPolicy),
        "Custom expiration" => ProgramTemporaryAllowance.CreateTimed(SelectedApplication!.Id, TemporaryAllowanceKind.CustomExpiration, now, SelectedPolicy, now.AddHours(2)),
        _ => null
    };

    private ConnectionCompatibilityExclusion? CreateCompatibilityExclusion(DateTimeOffset now, ProgramIdentity identity) => SelectedCompatibilityOption switch
    {
        "Selected program" => new(CompatibilityExclusionKind.Program, identity.StableId, "Allow only the selected stable program identity."),
        "Exact domain" => ConnectionCompatibilityExclusion.CreateDomain("example.com", "Allow only example.com for the selected program."),
        "15-minute bypass" => new(CompatibilityExclusionKind.TemporaryBypass, identity.StableId, "Allow only the selected program for 15 minutes.", now.AddMinutes(15)),
        _ => null
    };

    private static ProgramIdentity CreateProgramIdentity(InstalledApplicationInfo application)
    {
        if (!string.IsNullOrWhiteSpace(application.PackageFamilyName))
        {
            return ProgramIdentity.CreateMsix(application.Id, application.DisplayName, application.PackageFamilyName, application.Publisher, application.IsWindowsSystemComponent);
        }
        if (!string.IsNullOrWhiteSpace(application.MainExecutablePath))
        {
            return ProgramIdentity.CreateWin32(application.Id, application.DisplayName, application.MainExecutablePath, application.Publisher, application.ExecutableExists, application.IsWindowsSystemComponent);
        }
        return ProgramIdentity.Ambiguous(application.DisplayName, application.DiscoverySources.Count == 0 ? new[] { application.Id } : application.DiscoverySources);
    }
}
