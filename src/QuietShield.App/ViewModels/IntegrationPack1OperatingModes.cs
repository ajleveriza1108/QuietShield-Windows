using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Runtime.CompilerServices;
using System.Windows.Input;
using QuietShield.Core.DataSaving;

namespace QuietShield.App.ViewModels;

public sealed class DataSavingApplicationItem : INotifyPropertyChanged
{
    private bool _isAllowed;

    public DataSavingApplicationItem(ApplicationListItem application, bool isAllowed)
    {
        Id = application.Id;
        DisplayName = application.DisplayName;
        ApplicationTypeLabel = application.ApplicationTypeLabel;
        IsSystemComponent = application.Application.IsWindowsSystemComponent;
        _isAllowed = IsSystemComponent || isAllowed;
    }

    public event PropertyChangedEventHandler? PropertyChanged;

    public string Id { get; }

    public string DisplayName { get; }

    public string ApplicationTypeLabel { get; }

    public bool IsSystemComponent { get; }

    public bool CanUserChangeAccess => !IsSystemComponent;

    public string SafetyLabel => IsSystemComponent
        ? "SYSTEM â€¢ PROTECTED"
        : "USER APPLICATION";

    public bool IsAllowed
    {
        get => _isAllowed;
        set
        {
            var normalized = IsSystemComponent || value;
            if (_isAllowed == normalized)
            {
                return;
            }

            _isAllowed = normalized;
            OnPropertyChanged();
            OnPropertyChanged(nameof(AccessLabel));
        }
    }

    public string AccessLabel => IsSystemComponent
        ? "Windows safety boundary"
        : IsAllowed
            ? "Internet allowed in Data Saving"
            : "Blocked by Data Saving plan";

    private void OnPropertyChanged([CallerMemberName] string? propertyName = null) =>
        PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(propertyName));
}

public sealed partial class MainViewModel
{
    private readonly IOperatingModeStore _operatingModeStore;
    private OperatingModeState _operatingModeState = OperatingModeState.Default;
    private string _dataSavingProfileName = OperatingModeState.Default.ProfileName;
    private NetworkClassification _selectedNetworkClassification = OperatingModeState.Default.NetworkClassification;
    private string _dataSavingPlanSummary = "Profile has not been evaluated yet.";
    private string _operatingModeStatus = "Mode state is loading.";

    public ObservableCollection<DataSavingApplicationItem> DataSavingApplications { get; } = new();

    public IReadOnlyList<NetworkClassification> NetworkClassifications { get; } =
        Enum.GetValues<NetworkClassification>();

    public ICommand UseDataSavingModeCommand { get; private set; } = null!;

    public ICommand UseWiFiModeCommand { get; private set; } = null!;

    public ICommand SaveDataSavingProfileCommand { get; private set; } = null!;

    public QuietShieldOperatingMode OperatingMode => _operatingModeState.Mode;

    public string OperatingModeDisplay => OperatingMode == QuietShieldOperatingMode.DataSaving
        ? "Data Saving"
        : "Wi-Fi Mode";

    public bool IsDataSavingModeActive => OperatingMode == QuietShieldOperatingMode.DataSaving;

    public bool IsWiFiModeActive => OperatingMode == QuietShieldOperatingMode.WiFi;

    public string DataSavingProfileName
    {
        get => _dataSavingProfileName;
        set => SetField(ref _dataSavingProfileName, value);
    }

    public NetworkClassification SelectedNetworkClassification
    {
        get => _selectedNetworkClassification;
        set => SetField(ref _selectedNetworkClassification, value);
    }

    public string DataSavingPlanSummary
    {
        get => _dataSavingPlanSummary;
        private set => SetField(ref _dataSavingPlanSummary, value);
    }

    public string OperatingModeStatus
    {
        get => _operatingModeStatus;
        private set => SetField(ref _operatingModeStatus, value);
    }

    public string DataSavingEnforcementStatus
    {
        get
        {
            return OperatingMode == QuietShieldOperatingMode.DataSaving
                ? "Data Saving profile and tray state are live locally. Batch Firewall enforcement is intentionally not applied in Integration Pack 1."
                : "Wi-Fi Mode and tray state are live locally. Data Saving batch Firewall enforcement remains inactive in Integration Pack 1.";
        }
    }

    private void InitializeOperatingModeCommands()
    {
        UseDataSavingModeCommand = new AsyncRelayCommand(
            () => SetOperatingModeAsync(QuietShieldOperatingMode.DataSaving));

        UseWiFiModeCommand = new AsyncRelayCommand(
            () => SetOperatingModeAsync(QuietShieldOperatingMode.WiFi));

        SaveDataSavingProfileCommand = new AsyncRelayCommand(SaveOperatingModeProfileAsync);
    }

    private async Task InitializeOperatingModeAsync(CancellationToken cancellationToken)
    {
        _operatingModeState = await _operatingModeStore.LoadAsync(cancellationToken).ConfigureAwait(true);
        _dataSavingProfileName = _operatingModeState.ProfileName;
        _selectedNetworkClassification = _operatingModeState.NetworkClassification;
        RaiseOperatingModeProperties();

        OperatingModeStatus = OperatingMode == QuietShieldOperatingMode.DataSaving
            ? "Data Saving preference restored."
            : "Wi-Fi Mode preference restored.";
    }

    private async Task SetOperatingModeAsync(QuietShieldOperatingMode mode)
    {
        _operatingModeState = CaptureOperatingModeState() with { Mode = mode };
        await _operatingModeStore.SaveAsync(_operatingModeState, CancellationToken.None).ConfigureAwait(true);
        RaiseOperatingModeProperties();
        UpdateDataSavingPlanPreview();

        OperatingModeStatus = mode == QuietShieldOperatingMode.DataSaving
            ? "Data Saving selected. Only the local plan is active until batch enforcement is explicitly enabled later."
            : "Wi-Fi Mode selected. User applications remain unrestricted by the Data Saving plan.";
    }

    private async Task SaveOperatingModeProfileAsync()
    {
        _operatingModeState = CaptureOperatingModeState();
        await _operatingModeStore.SaveAsync(_operatingModeState, CancellationToken.None).ConfigureAwait(true);
        UpdateDataSavingPlanPreview();
        OperatingModeStatus = "Data Saving profile saved locally.";
    }

    private OperatingModeState CaptureOperatingModeState()
    {
        var allowedIds = DataSavingApplications
            .Where(static application => !application.IsSystemComponent && application.IsAllowed)
            .Select(static application => application.Id)
            .Distinct(StringComparer.Ordinal)
            .OrderBy(static id => id, StringComparer.Ordinal)
            .ToArray();

        return new OperatingModeState(
            OperatingMode,
            DataSavingProfileName,
            SelectedNetworkClassification,
            allowedIds).Normalize();
    }

    private void RebuildDataSavingApplications()
    {
        var selected = new HashSet<string>(
            _operatingModeState.AllowedApplicationIds,
            StringComparer.Ordinal);

        DataSavingApplications.Clear();

        foreach (var application in _allApplications.OrderBy(static item => item.DisplayName, StringComparer.CurrentCultureIgnoreCase))
        {
            DataSavingApplications.Add(new DataSavingApplicationItem(
                application,
                selected.Contains(application.Id)));
        }

        UpdateDataSavingPlanPreview();
    }

    private void UpdateDataSavingPlanPreview()
    {
        var current = CaptureOperatingModeState();
        var descriptors = DataSavingApplications
            .Select(static application => new DataSavingApplicationDescriptor(
                application.Id,
                application.IsSystemComponent))
            .ToArray();

        var plan = DataSavingPolicyPlanner.Build(descriptors, current);

        var blocked = plan.Applications.Count(static application =>
            application.Decision == DataSavingAccessDecision.Blocked);

        var allowed = plan.Applications.Count(static application =>
            application.Decision == DataSavingAccessDecision.Allowed);

        var protectedSystem = plan.Applications.Count(static application =>
            application.Decision == DataSavingAccessDecision.SystemProtected);

        DataSavingPlanSummary = OperatingMode == QuietShieldOperatingMode.DataSaving
            ? $"{allowed} user app(s) allowed â€¢ {blocked} planned blocked â€¢ {protectedSystem} Windows system component(s) protected"
            : $"{allowed} user app(s) unrestricted â€¢ {protectedSystem} Windows system component(s) protected";
    }

    private void RaiseOperatingModeProperties()
    {
        OnPropertyChanged(nameof(OperatingMode));
        OnPropertyChanged(nameof(OperatingModeDisplay));
        OnPropertyChanged(nameof(IsDataSavingModeActive));
        OnPropertyChanged(nameof(IsWiFiModeActive));
        OnPropertyChanged(nameof(DataSavingProfileName));
        OnPropertyChanged(nameof(SelectedNetworkClassification));
        OnPropertyChanged(nameof(DataSavingEnforcementStatus));
    }
}
