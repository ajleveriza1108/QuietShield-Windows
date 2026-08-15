using System.Text.Json;
using QuietShield.Core.ConnectionLock.Transactions;
using QuietShield.Core.Protection;

namespace QuietShield.Core.ServiceFoundation;

public static class QuietShieldServiceProtocol
{
    public const int CurrentVersion = 1;
    public const int MaximumMessageBytes = 64 * 1024;
    public const string DefaultPipeName = "QuietShield.Service.Diagnostic.v1";
    public const string ProductionPipeName = "QuietShield.Service.v1";
    public static readonly TimeSpan DefaultTimeout = TimeSpan.FromSeconds(5);
    public const string NotActiveMessage = "NotActive \u2014 service installation and enforcement not enabled.";
}

public enum ServiceMessageKind
{
    GetServiceStatus,
    GetActiveProfile,
    PreviewPolicyPlan,
    RequestProfileActivation,
    RequestProgramRuleChange,
    RequestTemporaryAllowance,
    GetTransactionStatus,
    RequestRollback,
    GetHealth,
    GetBackendStatus,
    GetProtectionStatistics,
    RunBackendSelfTest,
    RequestDnsShieldActivation,
    RequestOperatingModeEnforcement,
    ReportPrivateBrowserBlockEvent,
    RequestFileSafetyScan,
    Ping
}

public enum ServiceResponseStatus
{
    Ok,
    NotActive,
    InvalidRequest,
    UnsupportedProtocol,
    InternalError
}

public sealed record ServiceRequest(
    int ProtocolVersion,
    Guid RequestId,
    ServiceMessageKind MessageKind,
    JsonElement Payload);

public sealed record ServiceResponse(
    int ProtocolVersion,
    Guid RequestId,
    ServiceResponseStatus Status,
    string Message,
    JsonElement Payload);

public sealed record ServiceStatusSnapshot(
    string InstallationStatus,
    string CommunicationStatus,
    string PersistentEnforcementStatus,
    string ActiveProfile,
    string LastKnownGoodPolicyStatus,
    string TransactionStatus,
    string RecoveryReadiness,
    DateTimeOffset UpdatedAtUtc,
    bool ServiceInstalled = false,
    bool ServiceRunning = false,
    bool IpcConnected = false,
    bool PersistentEnforcementAvailable = false,
    IReadOnlyList<PersistentProgramPolicy>? ProgramPolicies = null,
    Guid? ProgramChangeAuthorizationId = null);

public sealed record ServiceHealthSnapshot(
    string State,
    long HeartbeatSequence,
    DateTimeOffset? LastHeartbeatUtc,
    string PreflightStatus,
    bool StateIntegrityValid,
    bool InterruptedTransactionDetected,
    string Detail);

public sealed record PolicyPreviewRequest(ProgramConnectionPolicy Policy);

public sealed record ProgramRuleChangeRequest(
    Guid ApprovedRehearsalId,
    string ProfileId,
    string StableApplicationIdentity,
    string ExecutablePath,
    string ExecutableSha256,
    ProgramConnectionPolicy Policy);

public sealed record ProgramRuleChangeResponse(
    Guid TransactionId,
    ProgramConnectionPolicy Policy,
    string ExactRuleName,
    string TransactionStatus,
    bool ExactRulePresent,
    IReadOnlyList<string> VisibleSafetyExemptions);

public sealed record PolicyPreviewResponse(
    ProgramConnectionPolicy Policy,
    PolicyEnforcementSupport Support,
    ProposedEnforcementLayer Layer,
    bool CanPersistentlyEnforce,
    string Classification,
    string Reason,
    IReadOnlyList<string> VisibleSafetyExemptions);

public sealed record BackendStatusSnapshotR40(
    bool DnsRuntimeRunning,
    bool DnsSystemActive,
    bool DnsDesiredEnabled,
    bool DataSavingEnforcementActive,
    int DataSavingRuleCount,
    bool ProgramConnectionLockAvailable,
    bool PrivateBrowserFilteringAvailable,
    bool FileSafetyAvailable,
    bool ParentChildBackendAvailable,
    bool ScheduleBackendAvailable,
    bool TelemetryBackendAvailable,
    bool LicensingBackendAvailable,
    bool UpdaterBackendAvailable,
    bool TrayBackendAvailable,
    string OverallStatus,
    string Detail);

public sealed record ProtectionStatisticsSnapshotR40(
    string DateLocal,
    long AdsBlocked,
    long TrackersBlocked,
    long ThreatsBlocked,
    long TotalBlocked,
    DateTimeOffset UpdatedAtUtc,
    string Status);

public sealed record BackendSelfTestCheckR40(
    string Name,
    bool Passed,
    string Detail);

public sealed record BackendSelfTestResultR40(
    bool Passed,
    IReadOnlyList<BackendSelfTestCheckR40> Checks,
    string Summary,
    DateTimeOffset CompletedAtUtc);

public sealed record DnsShieldActivationRequestR40(
    bool Enable,
    bool ExplicitUserApproval);

public sealed record DnsShieldActivationResponseR40(
    bool Succeeded,
    bool SystemActive,
    bool ExternalProbeGatePassed,
    string Message);

public sealed record OperatingModeProgramTargetR40(
    string StableApplicationIdentity,
    string DisplayName,
    string? ExecutablePath,
    bool IsWindowsSystemComponent,
    bool Selected);

public sealed record OperatingModeEnforcementRequestR40(
    string Mode,
    IReadOnlyList<OperatingModeProgramTargetR40> Programs);

public sealed record OperatingModeEnforcementResponseR40(
    bool Succeeded,
    string ActiveMode,
    int ActiveRuleCount,
    string Message);

public sealed record PrivateBrowserBlockEventR40(
    string Host,
    string Category,
    DateTimeOffset OccurredAtUtc);

public sealed record FileSafetyScanRequestR40(
    string Path,
    bool RunDefenderForHighRisk);

public sealed record FileSafetyScanResponseR40(
    bool Succeeded,
    string Risk,
    string Sha256,
    bool DefenderScanStarted,
    int? DefenderExitCode,
    string Summary);
public interface IQuietShieldServiceRequestHandler
{
    Task<ServiceResponse> HandleAsync(ServiceRequest request, CancellationToken cancellationToken);
}

public interface IQuietShieldServiceClient
{
    Task<ServiceResponse> SendAsync(ServiceMessageKind messageKind, object? payload, CancellationToken cancellationToken);
}
