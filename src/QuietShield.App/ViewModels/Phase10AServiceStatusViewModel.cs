using System.IO;
using System.Text.Json;
using System.Windows.Input;
using QuietShield.Core.ServiceFoundation;

namespace QuietShield.App.ViewModels;

public sealed partial class MainViewModel
{
    private ServiceStatusSnapshot? _lastServiceStatus;
    private string _serviceInstallationStatus = "Service endpoint not connected";
    private string _serviceCommunicationStatus = "Not connected";
    private string _persistentEnforcementStatus = "Not available until the service is running";
    private string _serviceActiveProfile = "Unavailable";
    private string _lastKnownGoodPolicyStatus = "Unavailable";
    private string _serviceTransactionStatus = "Unavailable";
    private string _serviceRecoveryReadiness = "Unavailable";
    private string _serviceInstalled = "Unknown";
    private string _serviceRunning = "Unknown";
    private string _serviceIpcConnected = "No";
    private string _persistentEnforcementAvailable = "No";

    public string ServiceInstallationStatus { get => _serviceInstallationStatus; private set => SetField(ref _serviceInstallationStatus, value); }
    public string ServiceCommunicationStatus { get => _serviceCommunicationStatus; private set => SetField(ref _serviceCommunicationStatus, value); }
    public string PersistentEnforcementStatus { get => _persistentEnforcementStatus; private set => SetField(ref _persistentEnforcementStatus, value); }
    public string ServiceActiveProfile { get => _serviceActiveProfile; private set => SetField(ref _serviceActiveProfile, value); }
    public string LastKnownGoodPolicyStatus { get => _lastKnownGoodPolicyStatus; private set => SetField(ref _lastKnownGoodPolicyStatus, value); }
    public string ServiceTransactionStatus { get => _serviceTransactionStatus; private set => SetField(ref _serviceTransactionStatus, value); }
    public string ServiceRecoveryReadiness { get => _serviceRecoveryReadiness; private set => SetField(ref _serviceRecoveryReadiness, value); }
    public string ServiceInstalled { get => _serviceInstalled; private set => SetField(ref _serviceInstalled, value); }
    public string ServiceRunning { get => _serviceRunning; private set => SetField(ref _serviceRunning, value); }
    public string ServiceIpcConnected { get => _serviceIpcConnected; private set => SetField(ref _serviceIpcConnected, value); }
    public string PersistentEnforcementAvailable { get => _persistentEnforcementAvailable; private set => SetField(ref _persistentEnforcementAvailable, value); }

    public ICommand RefreshServiceStatusCommand { get; private set; } = null!;

    private void InitializePhase11ServiceIntegration()
    {
        RefreshServiceStatusCommand = new AsyncRelayCommand(
            () => RefreshPersistentServiceStatusAsync(CancellationToken.None));
    }

    private Task InitializePersistentServiceFoundationAsync(CancellationToken cancellationToken) =>
        RefreshPersistentServiceStatusAsync(cancellationToken);

    public async Task RefreshPersistentServiceStatusAsync(CancellationToken cancellationToken)
    {
        try
        {
            var response = await CreateProductionServiceClientR3543().SendAsync(
                ServiceMessageKind.GetServiceStatus,
                null,
                cancellationToken).ConfigureAwait(true);

            if (response.Status != ServiceResponseStatus.Ok)
            {
                ApplyUnavailableServiceStatus($"Service returned {response.Status}.");
                return;
            }

            var status = response.Payload.Deserialize<ServiceStatusSnapshot>(ServiceMessageSerializer.Options);
            if (status is null)
            {
                ApplyUnavailableServiceStatus("Service returned an empty status payload.");
                return;
            }

            ServiceInstallationStatus = status.InstallationStatus;
            _lastServiceStatus = status;
            ServiceCommunicationStatus = status.CommunicationStatus;
            PersistentEnforcementStatus = status.PersistentEnforcementStatus;
            ServiceActiveProfile = status.ActiveProfile;
            LastKnownGoodPolicyStatus = status.LastKnownGoodPolicyStatus;
            ServiceTransactionStatus = status.TransactionStatus;
            ServiceRecoveryReadiness = status.RecoveryReadiness;
            ServiceInstalled = status.ServiceInstalled ? "Yes" : "No";
            ServiceRunning = status.ServiceRunning ? "Yes" : "No";
            ServiceIpcConnected = status.IpcConnected ? "Yes" : "No";
            PersistentEnforcementAvailable = status.PersistentEnforcementAvailable
                ? "Yes — validated service engine"
                : "No";
            ReconcilePhase11DWorkflow(false);
        }
        catch (Exception exception) when (
            exception is IOException or
            InvalidDataException or
            TimeoutException or
            OperationCanceledException)
        {
            _lastServiceStatus = null;
            ApplyUnavailableServiceStatus(
                cancellationToken.IsCancellationRequested
                    ? "Service status query cancelled."
                    : "Service endpoint unavailable.");
            ReconcilePhase11DWorkflow(true);
        }
    }

    private void ApplyUnavailableServiceStatus(string communication)
    {
        ServiceInstallationStatus = "Unavailable from IPC";
        ServiceCommunicationStatus = communication;
        PersistentEnforcementStatus = "Not available until the service is running";
        ServiceActiveProfile = "Unavailable";
        LastKnownGoodPolicyStatus = "Unavailable";
        ServiceTransactionStatus = "Unavailable";
        ServiceRecoveryReadiness = "Unavailable";
        ServiceInstalled = "Unknown";
        ServiceRunning = "No response";
        ServiceIpcConnected = "No";
        PersistentEnforcementAvailable = "No";
    }
}
