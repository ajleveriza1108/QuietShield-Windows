// QuietShield Backend Runtime Completion R4.0
using System.Text.Json;
using QuietShield.Core.ServiceFoundation;

namespace QuietShield.Service;

internal sealed class ProductionCompositeServiceRequestHandlerR40 :
    IQuietShieldServiceRequestHandler
{
    private readonly DiagnosticServiceRequestHandler _legacy;
    private readonly ProductionBackendRuntimeR40 _backend;

    public ProductionCompositeServiceRequestHandlerR40(
        DiagnosticServiceRequestHandler legacy,
        ProductionBackendRuntimeR40 backend)
    {
        _legacy = legacy;
        _backend = backend;
    }

    public async Task<ServiceResponse> HandleAsync(
        ServiceRequest request,
        CancellationToken cancellationToken)
    {
        if (request.ProtocolVersion != QuietShieldServiceProtocol.CurrentVersion)
            return Response(request, ServiceResponseStatus.UnsupportedProtocol, "Unsupported protocol version.", null);

        switch (request.MessageKind)
        {
            case ServiceMessageKind.GetBackendStatus:
                return Response(request, ServiceResponseStatus.Ok, "Backend status returned.", _backend.GetStatus());

            case ServiceMessageKind.GetProtectionStatistics:
                return Response(request, ServiceResponseStatus.Ok, "Protection statistics returned.", _backend.GetStatistics());

            case ServiceMessageKind.RunBackendSelfTest:
            {
                var result = await _backend.RunSelfTestAsync(cancellationToken).ConfigureAwait(false);
                return Response(
                    request,
                    result.Passed ? ServiceResponseStatus.Ok : ServiceResponseStatus.NotActive,
                    result.Summary,
                    result);
            }

            case ServiceMessageKind.RequestDnsShieldActivation:
            {
                var payload = Deserialize<DnsShieldActivationRequestR40>(request.Payload);
                if (payload is null)
                    return Response(request, ServiceResponseStatus.InvalidRequest, "A complete DNS Shield activation request is required.", null);

                var result = await _backend.SetDnsShieldAsync(payload, cancellationToken).ConfigureAwait(false);
                return Response(
                    request,
                    result.Succeeded ? ServiceResponseStatus.Ok : ServiceResponseStatus.NotActive,
                    result.Message,
                    result);
            }

            case ServiceMessageKind.RequestOperatingModeEnforcement:
            {
                var payload = Deserialize<OperatingModeEnforcementRequestR40>(request.Payload);
                if (payload is null)
                    return Response(request, ServiceResponseStatus.InvalidRequest, "A complete operating-mode enforcement request is required.", null);

                try
                {
                    var result = await _backend.ApplyOperatingModeAsync(payload, cancellationToken).ConfigureAwait(false);
                    return Response(
                        request,
                        result.Succeeded ? ServiceResponseStatus.Ok : ServiceResponseStatus.InvalidRequest,
                        result.Message,
                        result);
                }
                catch (Exception exception) when (
                    exception is IOException or InvalidDataException or
                    InvalidOperationException or UnauthorizedAccessException or NotSupportedException)
                {
                    return Response(request, ServiceResponseStatus.InvalidRequest, exception.Message, null);
                }
            }

            case ServiceMessageKind.ReportPrivateBrowserBlockEvent:
            {
                var payload = Deserialize<PrivateBrowserBlockEventR40>(request.Payload);
                if (payload is null)
                    return Response(request, ServiceResponseStatus.InvalidRequest, "A valid Private Browser block event is required.", null);

                _backend.RecordPrivateBrowserBlock(payload);
                return Response(request, ServiceResponseStatus.Ok, "Private Browser block event recorded.", new { recorded = true });
            }

            case ServiceMessageKind.RequestFileSafetyScan:
            {
                var payload = Deserialize<FileSafetyScanRequestR40>(request.Payload);
                if (payload is null || string.IsNullOrWhiteSpace(payload.Path))
                    return Response(request, ServiceResponseStatus.InvalidRequest, "An exact file path is required.", null);

                try
                {
                    var result = await _backend.ScanFileAsync(payload, cancellationToken).ConfigureAwait(false);
                    return Response(request, ServiceResponseStatus.Ok, result.Summary, result);
                }
                catch (Exception exception) when (
                    exception is IOException or InvalidDataException or
                    InvalidOperationException or UnauthorizedAccessException or NotSupportedException)
                {
                    return Response(request, ServiceResponseStatus.InvalidRequest, exception.Message, null);
                }
            }

            default:
                return await _legacy.HandleAsync(request, cancellationToken).ConfigureAwait(false);
        }
    }

    private static T? Deserialize<T>(JsonElement? payload)
    {
        if (!payload.HasValue)
            return default;

        try
        {
            return payload.Value.Deserialize<T>(ServiceMessageSerializer.Options);
        }
        catch (JsonException)
        {
            return default;
        }
    }

    private static ServiceResponse Response(
        ServiceRequest request,
        ServiceResponseStatus status,
        string message,
        object? payload) =>
        new(
            QuietShieldServiceProtocol.CurrentVersion,
            request.RequestId,
            status,
            message,
            ServiceMessageSerializer.ToPayload(payload));
}
