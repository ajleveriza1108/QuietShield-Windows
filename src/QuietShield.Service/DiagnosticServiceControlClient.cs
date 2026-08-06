using System.Text.Json;
using QuietShield.Core.ServiceFoundation;

namespace QuietShield.Service;

public static class DiagnosticServiceControlClient
{
    private static readonly JsonSerializerOptions OutputOptions = new() { WriteIndented = true };

    public static async Task<int> RunAsync(DiagnosticServiceOptions options, CancellationToken cancellationToken)
    {
        try
        {
            await using var stream = File.OpenRead(options.ControlRequestPath!);
            var request = await JsonSerializer.DeserializeAsync<ProgramRuleChangeRequest>(stream, ServiceMessageSerializer.Options, cancellationToken).ConfigureAwait(false)
                          ?? throw new InvalidDataException("The exact control request is empty.");
            var client = new NamedPipeQuietShieldServiceClient(options.PipeName, options.RequestTimeout, false);
            var response = await client.SendAsync(ServiceMessageKind.RequestProgramRuleChange, request, cancellationToken).ConfigureAwait(false);
            var output = JsonSerializer.Serialize(new { status = response.Status.ToString(), response.Message, response.Payload }, OutputOptions);
            Directory.CreateDirectory(Path.GetDirectoryName(options.ControlOutputPath!)!);
            await File.WriteAllTextAsync(options.ControlOutputPath!, output, cancellationToken).ConfigureAwait(false);
            Console.WriteLine(output);
            return response.Status == ServiceResponseStatus.Ok ? 0 : 4;
        }
        catch (Exception exception) when (exception is IOException or InvalidDataException or JsonException or TimeoutException or OperationCanceledException)
        {
            Console.Error.WriteLine($"Exact service control request failed: {exception.GetType().Name}: {exception.Message}");
            return 5;
        }
    }
}
