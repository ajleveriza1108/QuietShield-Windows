using System.Text.Json;
using QuietShield.Core.ConnectionLock.Transactions;
using QuietShield.Core.Protection;

namespace QuietShield.Core.ServiceFoundation;

public static class QuietShieldServiceProtocol
{
    public const int CurrentVersion = 1;
    public const int MaximumMessageBytes = 64 * 1024;
    public const string DefaultPipeName = "QuietShield.Service.Diagnostic.v1";
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
    DateTimeOffset UpdatedAtUtc);

public sealed record ServiceHealthSnapshot(
    string State,
    long HeartbeatSequence,
    DateTimeOffset? LastHeartbeatUtc,
    string PreflightStatus,
    bool StateIntegrityValid,
    bool InterruptedTransactionDetected,
    string Detail);

public sealed record PolicyPreviewRequest(ProgramConnectionPolicy Policy);

public sealed record PolicyPreviewResponse(
    ProgramConnectionPolicy Policy,
    PolicyEnforcementSupport Support,
    ProposedEnforcementLayer Layer,
    bool CanPersistentlyEnforce,
    string Classification,
    string Reason,
    IReadOnlyList<string> VisibleSafetyExemptions);

public interface IQuietShieldServiceRequestHandler
{
    Task<ServiceResponse> HandleAsync(ServiceRequest request, CancellationToken cancellationToken);
}

public interface IQuietShieldServiceClient
{
    Task<ServiceResponse> SendAsync(ServiceMessageKind messageKind, object? payload, CancellationToken cancellationToken);
}
