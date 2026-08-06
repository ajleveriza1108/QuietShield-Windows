using System.Text.Json;
using QuietShield.Core.Protection;
using QuietShield.Core.ServiceFoundation;

namespace QuietShield.Service;

public static class DiagnosticIpcSmoke
{
    private static readonly JsonSerializerOptions OutputOptions = new() { WriteIndented = true };

    public static async Task<int> RunAsync(DiagnosticServiceOptions options, CancellationToken cancellationToken)
    {
        try
        {
            var client = new NamedPipeQuietShieldServiceClient(options.PipeName, options.RequestTimeout,
                !options.PipeName.Equals(QuietShieldServiceProtocol.ProductionPipeName, StringComparison.Ordinal));
            var ping = await client.SendAsync(ServiceMessageKind.Ping, null, cancellationToken).ConfigureAwait(false);
            var status = await client.SendAsync(ServiceMessageKind.GetServiceStatus, null, cancellationToken).ConfigureAwait(false);
            var blocked = await client.SendAsync(ServiceMessageKind.PreviewPolicyPlan, new PolicyPreviewRequest(ProgramConnectionPolicy.Blocked), cancellationToken).ConfigureAwait(false);
            var allowed = await client.SendAsync(ServiceMessageKind.PreviewPolicyPlan, new PolicyPreviewRequest(ProgramConnectionPolicy.AllowedOnAll), cancellationToken).ConfigureAwait(false);
            var networkSpecific = await client.SendAsync(ServiceMessageKind.PreviewPolicyPlan, new PolicyPreviewRequest(ProgramConnectionPolicy.WiFiOnly), cancellationToken).ConfigureAwait(false);
            var modifying = await client.SendAsync(ServiceMessageKind.RequestProfileActivation, new { profileId = "diagnostic" }, cancellationToken).ConfigureAwait(false);
            var result = new
            {
                schemaVersion = 1,
                status = ping.Status == ServiceResponseStatus.Ok && status.Status == ServiceResponseStatus.Ok &&
                         blocked.Status == ServiceResponseStatus.Ok && allowed.Status == ServiceResponseStatus.Ok &&
                         networkSpecific.Status == ServiceResponseStatus.Ok && modifying.Status == ServiceResponseStatus.NotActive
                    ? "Passed" : "Failed",
                ping = ping.Message,
                serviceStatus = status.Payload,
                blockedPreview = blocked.Payload,
                allowedPreview = allowed.Payload,
                networkSpecificPreview = networkSpecific.Payload,
                modifyingRequestStatus = modifying.Status.ToString(),
                modifyingRequestMessage = modifying.Message
            };
            var json = JsonSerializer.Serialize(result, OutputOptions);
            if (options.OutputPath is not null)
            {
                Directory.CreateDirectory(Path.GetDirectoryName(options.OutputPath)!);
                await File.WriteAllTextAsync(options.OutputPath, json, cancellationToken).ConfigureAwait(false);
            }
            Console.WriteLine(json);
            return result.status == "Passed" ? 0 : 2;
        }
        catch (Exception exception) when (exception is IOException or InvalidDataException or TimeoutException or OperationCanceledException)
        {
            Console.Error.WriteLine($"Diagnostic IPC smoke failed: {exception.GetType().Name}: {exception.Message}");
            return 3;
        }
    }
}
