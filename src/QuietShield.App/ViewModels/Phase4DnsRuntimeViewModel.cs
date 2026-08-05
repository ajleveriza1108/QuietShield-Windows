using System.IO;
using System.Windows.Input;
using QuietShield.Core.Dns;

namespace QuietShield.App.ViewModels;

public sealed partial class MainViewModel
{
    private string _dnsRuntimeStatus = "Stopped — the runtime starts only for an explicit loopback diagnostic.";
    private string _dnsSimulationStatus = "Ready — policy decisions remain local simulation only.";
    private string _dnsUpstreamHealthStatus = "Not configured — no production upstream endpoint is embedded.";
    private string _dnsTransactionReadiness = "Not ready — activation prerequisites have not been approved.";
    private string _originalDnsBackupStatus = "Not created — Windows DNS has never been activated by QuietShield.";
    private string _dnsConfigurationLastKnownGoodStatus = "Not created — no system DNS transaction has been committed.";
    private string _emergencyRecoveryStatus = "Framework available; restore requires a validated QuietShield backup and explicit manual launch.";

    public string DnsRuntimeStatus { get => _dnsRuntimeStatus; private set => SetField(ref _dnsRuntimeStatus, value); }
    public string DnsSimulationStatus { get => _dnsSimulationStatus; private set => SetField(ref _dnsSimulationStatus, value); }
    public string DnsUpstreamHealthStatus { get => _dnsUpstreamHealthStatus; private set => SetField(ref _dnsUpstreamHealthStatus, value); }
    public string DnsTransactionReadiness { get => _dnsTransactionReadiness; private set => SetField(ref _dnsTransactionReadiness, value); }
    public string OriginalDnsBackupStatus { get => _originalDnsBackupStatus; private set => SetField(ref _originalDnsBackupStatus, value); }
    public string DnsConfigurationLastKnownGoodStatus { get => _dnsConfigurationLastKnownGoodStatus; private set => SetField(ref _dnsConfigurationLastKnownGoodStatus, value); }
    public string EmergencyRecoveryStatus { get => _emergencyRecoveryStatus; private set => SetField(ref _emergencyRecoveryStatus, value); }
    public string DnsEnforcementBanner { get; } = "DNS enforcement is not active. Windows DNS has not been changed.";
    public ICommand TestLocalDnsRuntimeCommand { get; private set; } = null!;
    public ICommand PreviewDnsActivationPlanCommand { get; private set; } = null!;

    private void InitializeDnsRuntimeCommands()
    {
        TestLocalDnsRuntimeCommand = new AsyncRelayCommand(TestLocalDnsRuntimeAsync, () => !IsRefreshing);
        PreviewDnsActivationPlanCommand = new AsyncRelayCommand(PreviewDnsActivationPlanAsync, () => !IsRefreshing);
    }

    private async Task TestLocalDnsRuntimeAsync()
    {
        DnsRuntimeStatus = "Running an explicit loopback-only UDP/TCP diagnostic on a dynamic unprivileged port…";
        try
        {
            using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(10));
            var result = await _dnsRuntimeDiagnostic.RunAsync(timeout.Token).ConfigureAwait(true);
            DnsRuntimeStatus = result.Succeeded
                ? $"Diagnostic passed on dynamic port {result.BoundPort}; the runtime stopped cleanly afterward."
                : result.Status;
            DnsSimulationStatus = result.Succeeded ? "Ready — blocked-domain policy simulation passed over UDP and TCP." : "Diagnostic failed; no activation was attempted.";
        }
        catch (Exception exception) when (exception is OperationCanceledException or InvalidOperationException or IOException or System.Net.Sockets.SocketException)
        {
            DnsRuntimeStatus = $"Diagnostic stopped safely: {exception.Message}";
        }
    }

    private Task PreviewDnsActivationPlanAsync()
    {
        var readiness = DnsTransactionReadinessEvaluator.Evaluate(
            explicitUserApproval: false,
            administratorContext: false,
            validatedBackup: false,
            activeLocalResolver: false,
            activeAdaptersSelected: false);
        DnsTransactionReadiness = readiness.Status + " Preview only; no modifying implementation was invoked.";
        OriginalDnsBackupStatus = "Not created by this preview; a future approved preflight must capture and validate it before activation.";
        DnsConfigurationLastKnownGoodStatus = "Unavailable until a separately approved transaction is verified and committed.";
        return Task.CompletedTask;
    }

    private void RaiseDnsRuntimeCommandStates()
    {
        foreach (var command in new[] { TestLocalDnsRuntimeCommand, PreviewDnsActivationPlanCommand }.OfType<AsyncRelayCommand>())
        {
            command.RaiseCanExecuteChanged();
        }
    }
}
