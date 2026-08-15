using System.IO;
using QuietShield.Core.ServiceFoundation;
using System.Text.Json;
using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Runtime.CompilerServices;
using System.Windows.Data;
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
        ExecutablePath = application.Application.MainExecutablePath;
        IsSystemComponent = application.Application.IsWindowsSystemComponent;
        _isAllowed = IsSystemComponent || isAllowed;
    }

    public event PropertyChangedEventHandler? PropertyChanged;

    public string Id { get; }
    public string DisplayName { get; }
    public string ApplicationTypeLabel { get; }

    public string? ExecutablePath { get; }
    public bool IsSystemComponent { get; }
    public bool CanUserChangeAccess => !IsSystemComponent;

    public string SafetyLabel => IsSystemComponent
        ? "SYSTEM - PROTECTED"
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
        ? "Protected Windows system component"
        : IsAllowed
            ? "Internet access allowed in Data Saving mode"
            : "Internet access planned to be blocked in Data Saving mode";

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
    private string _dataSavingEnforcementStatus = "Machine enforcement has not been requested yet.";
    private string _dataSavingSearchText = string.Empty;
    private string _selectedDataSavingFilter = "User apps";

    public ObservableCollection<DataSavingApplicationItem> DataSavingApplications { get; } = new();

    public ICollectionView DataSavingApplicationsView =>
        CollectionViewSource.GetDefaultView(DataSavingApplications);

    public IReadOnlyList<NetworkClassification> NetworkClassifications { get; } =
        Enum.GetValues<NetworkClassification>();

    public IReadOnlyList<string> DataSavingFilterOptions { get; } = new[]
    {
        "User apps",
        "Allowed",
        "Planned blocked",
        "System",
        "All"
    };

    public ICommand UseDataSavingModeCommand { get; private set; } = null!;
    public ICommand UseWiFiModeCommand { get; private set; } = null!;
    public ICommand SaveDataSavingProfileCommand { get; private set; } = null!;
    public ICommand AllowVisibleDataSavingAppsCommand { get; private set; } = null!;
    public ICommand BlockVisibleDataSavingAppsCommand { get; private set; } = null!;
    public ICommand RestoreDataSavingDefaultsCommand { get; private set; } = null!;

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

    public string DataSavingSearchText
    {
        get => _dataSavingSearchText;
        set
        {
            if (SetField(ref _dataSavingSearchText, value))
            {
                DataSavingApplicationsView.Refresh();
            }
        }
    }

    public string SelectedDataSavingFilter
    {
        get => _selectedDataSavingFilter;
        set
        {
            if (SetField(ref _selectedDataSavingFilter, value))
            {
                DataSavingApplicationsView.Refresh();
            }
        }
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
        get => _dataSavingEnforcementStatus;
        private set => SetField(ref _dataSavingEnforcementStatus, value);
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
        await ApplyOperatingModeMachineEnforcementR40Async(CancellationToken.None).ConfigureAwait(true);

        OperatingModeStatus = mode == QuietShieldOperatingMode.DataSaving
            ? "Data Saving selected. App selections are saved locally for testing."
            : "Wi-Fi Mode selected. User apps are not restricted by the Data Saving plan.";
    }

    private async Task SaveOperatingModeProfileAsync()
    {
        _operatingModeState = CaptureOperatingModeState();
        await _operatingModeStore.SaveAsync(_operatingModeState, CancellationToken.None).ConfigureAwait(true);
        UpdateDataSavingPlanPreview();
        await ApplyOperatingModeMachineEnforcementR40Async(CancellationToken.None).ConfigureAwait(true);
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
            var item = new DataSavingApplicationItem(
                application,
                selected.Contains(application.Id));

            item.PropertyChanged += OnDataSavingApplicationPropertyChanged;
            DataSavingApplications.Add(item);
        }

        DataSavingApplicationsView.Refresh();
        UpdateDataSavingPlanPreview();
    }

    private void OnDataSavingApplicationPropertyChanged(object? sender, PropertyChangedEventArgs args)
    {
        if (args.PropertyName == nameof(DataSavingApplicationItem.IsAllowed))
        {
            UpdateDataSavingPlanPreview();
            DataSavingApplicationsView.Refresh();
        }
    }

    private bool DataSavingFilterPredicate(object item)
    {
        if (item is not DataSavingApplicationItem application)
        {
            return false;
        }

        var query = DataSavingSearchText.Trim();
        if (!string.IsNullOrWhiteSpace(query) &&
            !application.DisplayName.Contains(query, StringComparison.CurrentCultureIgnoreCase) &&
            !application.ApplicationTypeLabel.Contains(query, StringComparison.CurrentCultureIgnoreCase))
        {
            return false;
        }

        return SelectedDataSavingFilter switch
        {
            "User apps" => !application.IsSystemComponent,
            "Allowed" => !application.IsSystemComponent && application.IsAllowed,
            "Planned blocked" => !application.IsSystemComponent && !application.IsAllowed,
            "System" => application.IsSystemComponent,
            _ => true
        };
    }

    private void SetVisibleDataSavingAccess(bool allowed)
    {
        foreach (var application in DataSavingApplications
                     .Where(item => DataSavingFilterPredicate(item) && item.CanUserChangeAccess)
                     .ToArray())
        {
            application.IsAllowed = allowed;
        }

        UpdateDataSavingPlanPreview();
        OperatingModeStatus = allowed
            ? "Visible user apps marked allowed. Save Profile to persist the selection."
            : "Visible user apps marked blocked in the local plan. Save Profile to persist the selection.";
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
            ? $"{allowed} allowed user apps | {blocked} user apps planned to be blocked | {protectedSystem} protected Windows system components"
            : $"{allowed} unrestricted user apps | {protectedSystem} protected Windows system components";
    }

    private async Task ApplyOperatingModeMachineEnforcementR40Async(
        CancellationToken cancellationToken)
    {
        try
        {
            var targets =
                DataSavingApplications
                    .Select(item =>
                        new OperatingModeProgramTargetR40(
                            item.Id,
                            item.DisplayName,
                            item.ExecutablePath,
                            item.IsSystemComponent,
                            item.IsAllowed))
                    .ToArray();

            var response =
                await _serviceClient.SendAsync(
                        ServiceMessageKind.RequestOperatingModeEnforcement,
                        new OperatingModeEnforcementRequestR40(
                            IsDataSavingModeActive ? "DataSaving" : "WiFi",
                            targets),
                        cancellationToken)
                    .ConfigureAwait(true);

            var result =
                response.Payload.Deserialize<OperatingModeEnforcementResponseR40>(
                    ServiceMessageSerializer.Options);

            DataSavingEnforcementStatus =
                response.Status == ServiceResponseStatus.Ok
                    ? result?.Message ?? response.Message
                    : "Machine enforcement failed safely: " + response.Message;
        }
        catch (Exception exception) when (
            exception is IOException or
            TimeoutException or
            InvalidDataException or
            JsonException or
            OperationCanceledException)
        {
            DataSavingEnforcementStatus =
                "Machine enforcement is unavailable: " +
                exception.Message;
        }
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
