using System.Text.Json;
using QuietShield.Core.ServiceFoundation;

namespace QuietShield.Service;

public sealed class DiagnosticServiceRequestHandler : IQuietShieldServiceRequestHandler
{
    private static readonly HashSet<ServiceMessageKind> ModifyingRequests =
    [
        ServiceMessageKind.RequestProfileActivation,
        ServiceMessageKind.RequestProgramRuleChange,
        ServiceMessageKind.RequestTemporaryAllowance,
        ServiceMessageKind.RequestRollback
    ];

    private readonly PersistentServiceRuntime _runtime;
    private readonly IPersistentPolicyCoordinator _coordinator;

    public DiagnosticServiceRequestHandler(PersistentServiceRuntime runtime, IPersistentPolicyCoordinator coordinator)
    {
        _runtime = runtime;
        _coordinator = coordinator;
    }

    public async Task<ServiceResponse> HandleAsync(ServiceRequest request, CancellationToken cancellationToken)
    {
        if (request.ProtocolVersion != QuietShieldServiceProtocol.CurrentVersion)
            return Response(request, ServiceResponseStatus.UnsupportedProtocol, "Unsupported protocol version.", null);
        if (ModifyingRequests.Contains(request.MessageKind))
            return Response(request, ServiceResponseStatus.NotActive, QuietShieldServiceProtocol.NotActiveMessage, null);

        return request.MessageKind switch
        {
            ServiceMessageKind.Ping => Response(request, ServiceResponseStatus.Ok, "Pong", new { utc = DateTimeOffset.UtcNow }),
            ServiceMessageKind.GetServiceStatus => Response(request, ServiceResponseStatus.Ok, "Service status returned.", _runtime.GetStatus()),
            ServiceMessageKind.GetActiveProfile => Response(request, ServiceResponseStatus.Ok, "Active profile returned.", new { profileId = _runtime.GetState().ActiveProfileId }),
            ServiceMessageKind.GetTransactionStatus => Response(request, ServiceResponseStatus.Ok, "Transaction status returned.", _runtime.GetState().TransactionCheckpoint),
            ServiceMessageKind.GetHealth => Response(request, ServiceResponseStatus.Ok, "Health returned.", _runtime.GetHealth()),
            ServiceMessageKind.PreviewPolicyPlan => await PreviewAsync(request, cancellationToken).ConfigureAwait(false),
            _ => Response(request, ServiceResponseStatus.InvalidRequest, "The request kind is unsupported.", null)
        };
    }

    private async Task<ServiceResponse> PreviewAsync(ServiceRequest request, CancellationToken cancellationToken)
    {
        PolicyPreviewRequest? preview;
        try { preview = request.Payload.Deserialize<PolicyPreviewRequest>(ServiceMessageSerializer.Options); }
        catch (JsonException) { preview = null; }
        if (preview is null || !Enum.IsDefined(preview.Policy))
            return Response(request, ServiceResponseStatus.InvalidRequest, "A supported policy value is required for preview.", null);
        var plan = await _coordinator.PreviewAsync(preview.Policy, cancellationToken).ConfigureAwait(false);
        var supported = plan.Enforceability.Support == Core.ConnectionLock.Transactions.PolicyEnforcementSupport.WindowsFirewallStatic &&
                        preview.Policy is Core.Protection.ProgramConnectionPolicy.Blocked or Core.Protection.ProgramConnectionPolicy.AllowedOnAll;
        var result = new PolicyPreviewResponse(
            preview.Policy,
            plan.Enforceability.Support,
            plan.Enforceability.Layer,
            false,
            supported ? "Supported eventual policy; Phase 10A remains read-only" : plan.Enforceability.Support.ToString(),
            plan.Enforceability.Reason,
            plan.SafetyExemptions.Select(static exemption => $"{exemption.Kind}: {exemption.VisibleReason}").ToArray());
        return Response(request, ServiceResponseStatus.Ok, "Read-only policy preview returned.", result);
    }

    private static ServiceResponse Response(ServiceRequest request, ServiceResponseStatus status, string message, object? payload) =>
        new(QuietShieldServiceProtocol.CurrentVersion, request.RequestId, status, message, ServiceMessageSerializer.ToPayload(payload));
}
