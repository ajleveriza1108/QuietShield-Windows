using System.Text.Json;
using QuietShield.Core.ServiceFoundation;

var client = new NamedPipeQuietShieldServiceClient(
    QuietShieldServiceProtocol.ProductionPipeName,
    // R4.2.3 diagnostic IPC budget: the self-test now includes live UDP/TCP
    // listener health plus File Safety and the existing backend checks.
    TimeSpan.FromSeconds(60),
    currentUserOnly: false);

var command = args.FirstOrDefault()?.Trim().ToLowerInvariant() ?? "--self-test";

var kind = command switch
{
    "--self-test" => ServiceMessageKind.RunBackendSelfTest,
    "--status" => ServiceMessageKind.GetBackendStatus,
    "--stats" => ServiceMessageKind.GetProtectionStatistics,
    "--dns-on" => ServiceMessageKind.RequestDnsShieldActivation,
    "--dns-off" => ServiceMessageKind.RequestDnsShieldActivation,
    _ => throw new ArgumentException(
        "Use --self-test, --status, --stats, --dns-on, or --dns-off.")
};

object? payload = command switch
{
    "--dns-on" => new DnsShieldActivationRequestR40(true, true),
    "--dns-off" => new DnsShieldActivationRequestR40(false, true),
    _ => null
};

var response = await client.SendAsync(kind, payload, CancellationToken.None);

Console.WriteLine(
    JsonSerializer.Serialize(
        response,
        new JsonSerializerOptions(ServiceMessageSerializer.Options)
        {
            WriteIndented = true
        }));

return response.Status == ServiceResponseStatus.Ok ? 0 : 2;
