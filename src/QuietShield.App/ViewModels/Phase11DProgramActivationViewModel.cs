using System.IO;
using System.Windows.Input;
using QuietShield.Core.Protection;
using QuietShield.Core.ServiceFoundation;

namespace QuietShield.App.ViewModels;

public sealed partial class MainViewModel
{
    private string _persistentWorkflowState = "Unavailable";
    private string _persistentWorkflowApplication = "No application selected";
    private string _persistentWorkflowIdentity = "No exact executable identity selected";
    private string _persistentWorkflowRequestedPolicy = "Allowed on All";
    private string _persistentWorkflowMessage = "Persistent service status has not been checked.";
    private string _persistentWorkflowIssue = "None";
    private string _persistentWorkflowFallback = "Network-specific policies continue in safe simulation mode.";
    private bool _persistentWorkflowBusy;

    public string PersistentWorkflowState { get => _persistentWorkflowState; private set => SetField(ref _persistentWorkflowState, value); }
    public string PersistentWorkflowApplication { get => _persistentWorkflowApplication; private set => SetField(ref _persistentWorkflowApplication, value); }
    public string PersistentWorkflowIdentity { get => _persistentWorkflowIdentity; private set => SetField(ref _persistentWorkflowIdentity, value); }
    public string PersistentWorkflowRequestedPolicy { get => _persistentWorkflowRequestedPolicy; private set => SetField(ref _persistentWorkflowRequestedPolicy, value); }
    public string PersistentWorkflowMessage { get => _persistentWorkflowMessage; private set => SetField(ref _persistentWorkflowMessage, value); }
    public string PersistentWorkflowIssue { get => _persistentWorkflowIssue; private set => SetField(ref _persistentWorkflowIssue, value); }
    public string PersistentWorkflowFallback { get => _persistentWorkflowFallback; private set => SetField(ref _persistentWorkflowFallback, value); }
    public bool PersistentWorkflowBusy { get => _persistentWorkflowBusy; private set { if (SetField(ref _persistentWorkflowBusy, value)) RaisePhase11DCommandStates(); } }
    public bool PersistentWorkflowCanSave => !PersistentWorkflowBusy &&
        SelectedApplication is { Application.MainExecutablePath: not null, Application.ExecutableExists: true, Application.IsWindowsSystemComponent: false } &&
        string.IsNullOrWhiteSpace(SelectedApplication.Application.PackageFamilyName) &&
        SelectedPolicy is ProgramConnectionPolicy.Blocked or ProgramConnectionPolicy.AllowedOnAll &&
        _lastServiceStatus is { ServiceInstalled: true, ServiceRunning: true, IpcConnected: true, PersistentEnforcementAvailable: true, ProgramChangeAuthorizationId: not null };

    public ICommand SavePersistentProgramPolicyCommand { get; private set; } = null!;
    public ICommand RetryPersistentServiceConnectionCommand { get; private set; } = null!;

    private void InitializePhase11DProgramActivation()
    {
        SavePersistentProgramPolicyCommand = new AsyncRelayCommand(SavePersistentProgramPolicyAsync, () => PersistentWorkflowCanSave);
        RetryPersistentServiceConnectionCommand = new AsyncRelayCommand(RetryPersistentServiceConnectionAsync, () => !PersistentWorkflowBusy);
    }

    private async Task LoadPhase11DDesktopPolicyAsync(CancellationToken cancellationToken) =>
        ApplyPhase11DSnapshot(await _desktopProgramActivation.LoadAsync(cancellationToken).ConfigureAwait(true));

    private async Task SavePersistentProgramPolicyAsync()
    {
        if (SelectedApplication is null) return;
        PersistentWorkflowBusy = true;
        PersistentWorkflowState = DesktopActivationState.Applying.ToString();
        PersistentWorkflowMessage = "Validating the exact application identity before contacting the service.";
        try
        {
            var application = SelectedApplication.Application;
            var capture = await _desktopProgramActivation.CaptureAsync(
                new(SelectedApplication.DisplayName, application.MainExecutablePath, application.PackageFamilyName, application.IsWindowsSystemComponent),
                SelectedConnectionProfile.Id,
                SelectedPolicy,
                CancellationToken.None).ConfigureAwait(true);
            if (!capture.IsValid)
            {
                ApplyPhase11DSnapshot(new(DesktopActivationState.Failed, capture.Issue, capture.CustomerMessage, _desktopProgramActivation.SavedConfiguration));
                return;
            }
            ApplyPhase11DSnapshot(await _desktopProgramActivation.ApplyAsync(capture.Configuration!, GetPhase11DServiceObservation(), CancellationToken.None).ConfigureAwait(true));
            if (PersistentWorkflowState == DesktopActivationState.Applied.ToString())
                await RefreshPersistentServiceStatusAsync(CancellationToken.None).ConfigureAwait(true);
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException or InvalidDataException)
        {
            ApplyPhase11DSnapshot(new(DesktopActivationState.Failed, DesktopActivationIssue.UnsupportedTarget,
                "The selected application could not be validated. No policy request was sent.", _desktopProgramActivation.SavedConfiguration));
        }
        finally { PersistentWorkflowBusy = false; }
    }

    private async Task RetryPersistentServiceConnectionAsync()
    {
        PersistentWorkflowBusy = true;
        try
        {
            await RefreshAsync(false).ConfigureAwait(true);
            await RefreshPersistentServiceStatusAsync(CancellationToken.None).ConfigureAwait(true);
        }
        finally { PersistentWorkflowBusy = false; }
    }

    private void UpdatePhase11DSelection()
    {
        PersistentWorkflowApplication = SelectedApplication?.DisplayName ?? "No application selected";
        PersistentWorkflowRequestedPolicy = SelectedPolicy == ProgramConnectionPolicy.AllowedOnAll ? "Allowed on All" : SelectedPolicy.ToString();
        try
        {
            PersistentWorkflowIdentity = SelectedApplication?.Application.MainExecutablePath is { } executable
                ? ApprovedProgramTargetIdentity.FromExecutablePath(executable)
                : SelectedApplication?.Application.PackageFamilyName is not null
                    ? "MSIX identity selected — persistent support is not active"
                    : "No exact executable identity selected";
        }
        catch (Exception exception) when (exception is ArgumentException or NotSupportedException or PathTooLongException)
        {
            PersistentWorkflowIdentity = "Invalid executable identity";
        }
        if (SelectedPolicy is not (ProgramConnectionPolicy.Blocked or ProgramConnectionPolicy.AllowedOnAll))
        {
            PersistentWorkflowState = DesktopActivationState.SimulationOnly.ToString();
            PersistentWorkflowIssue = DesktopActivationIssue.UnsupportedPersistentPolicy.ToString();
            PersistentWorkflowMessage = "This network-specific policy remains simulation-only and will not be sent to the service.";
        }
        else if (_lastServiceStatus?.PersistentEnforcementAvailable == true)
        {
            PersistentWorkflowState = DesktopActivationState.Ready.ToString();
            PersistentWorkflowIssue = DesktopActivationIssue.None.ToString();
            PersistentWorkflowMessage = "Review the exact application and save the requested persistent policy.";
        }
        RaisePhase11DCommandStates();
    }

    private void ReconcilePhase11DWorkflow(bool ipcFailed) =>
        ApplyPhase11DSnapshot(_desktopProgramActivation.Reconcile(GetPhase11DServiceObservation(), _lastServiceStatus, ipcFailed));

    private DesktopServiceObservation GetPhase11DServiceObservation()
    {
        var discovered = _bundle?.Services?.QuietShieldService;
        if (discovered is not null) return new(discovered.Registered, discovered.Running);
        return new(_lastServiceStatus?.ServiceInstalled == true, _lastServiceStatus?.ServiceRunning == true);
    }

    private void ApplyPhase11DSnapshot(DesktopProgramActivationSnapshot snapshot)
    {
        PersistentWorkflowState = snapshot.State.ToString();
        PersistentWorkflowIssue = snapshot.Issue.ToString();
        PersistentWorkflowMessage = snapshot.CustomerMessage;
        PersistentWorkflowFallback = snapshot.Issue switch
        {
            DesktopActivationIssue.ServiceUnavailable => "The desktop remains usable in simulation mode; it never installs the service itself.",
            DesktopActivationIssue.ServiceStopped => "Use the approved QuietShield lifecycle recovery path; the desktop will not start services or self-elevate.",
            DesktopActivationIssue.IpcFailure => "Retry the secure local connection. Existing service state remains authoritative.",
            DesktopActivationIssue.TransactionRolledBack => "Wait for validated service recovery. Stale desktop state will not overwrite last-known-good state.",
            DesktopActivationIssue.UnsupportedPersistentPolicy => "Continue using deterministic simulation for network-specific choices.",
            _ => "Blocked and Allowed on All are the only customer-capable persistent policies in Phase 11D."
        };
        RaisePhase11DCommandStates();
    }

    private void RaisePhase11DCommandStates()
    {
        OnPropertyChanged(nameof(PersistentWorkflowCanSave));
        (SavePersistentProgramPolicyCommand as AsyncRelayCommand)?.RaiseCanExecuteChanged();
        (RetryPersistentServiceConnectionCommand as AsyncRelayCommand)?.RaiseCanExecuteChanged();
    }
}
