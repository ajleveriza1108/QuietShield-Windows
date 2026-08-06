using System.IO;
using System.Text.Json;
using QuietShield.Core.ServiceFoundation;

namespace QuietShield.App.ViewModels;

public sealed partial class MainViewModel
{
    private string _serviceInstallationStatus = "Not installed";
    private string _serviceCommunicationStatus = "Diagnostic mode (not connected)";
    private string _persistentEnforcementStatus = "Not active";
    private string _serviceActiveProfile = "Unavailable until diagnostic communication succeeds";
    private string _lastKnownGoodPolicyStatus = "Not yet queried";
    private string _serviceTransactionStatus = "Not yet queried";
    private string _serviceRecoveryReadiness = "Not yet queried";

    public string ServiceInstallationStatus { get => _serviceInstallationStatus; private set => SetField(ref _serviceInstallationStatus, value); }
    public string ServiceCommunicationStatus { get => _serviceCommunicationStatus; private set => SetField(ref _serviceCommunicationStatus, value); }
    public string PersistentEnforcementStatus { get => _persistentEnforcementStatus; private set => SetField(ref _persistentEnforcementStatus, value); }
    public string ServiceActiveProfile { get => _serviceActiveProfile; private set => SetField(ref _serviceActiveProfile, value); }
    public string LastKnownGoodPolicyStatus { get => _lastKnownGoodPolicyStatus; private set => SetField(ref _lastKnownGoodPolicyStatus, value); }
    public string ServiceTransactionStatus { get => _serviceTransactionStatus; private set => SetField(ref _serviceTransactionStatus, value); }
    public string ServiceRecoveryReadiness { get => _serviceRecoveryReadiness; private set => SetField(ref _serviceRecoveryReadiness, value); }

    private async Task InitializePersistentServiceFoundationAsync(CancellationToken cancellationToken)
    {
        try
        {
            var response = await _serviceClient.SendAsync(ServiceMessageKind.GetServiceStatus, null, cancellationToken).ConfigureAwait(true);
            if (response.Status != ServiceResponseStatus.Ok) return;
            var status = response.Payload.Deserialize<ServiceStatusSnapshot>(ServiceMessageSerializer.Options);
            if (status is null) return;
            ServiceInstallationStatus = status.InstallationStatus;
            ServiceCommunicationStatus = status.CommunicationStatus;
            PersistentEnforcementStatus = status.PersistentEnforcementStatus;
            ServiceActiveProfile = status.ActiveProfile;
            LastKnownGoodPolicyStatus = status.LastKnownGoodPolicyStatus;
            ServiceTransactionStatus = status.TransactionStatus;
            ServiceRecoveryReadiness = status.RecoveryReadiness;
        }
        catch (Exception exception) when (exception is IOException or InvalidDataException or TimeoutException or OperationCanceledException)
        {
            ServiceCommunicationStatus = cancellationToken.IsCancellationRequested
                ? "Diagnostic mode (query cancelled)"
                : "Diagnostic mode (service endpoint unavailable)";
        }
    }
}
