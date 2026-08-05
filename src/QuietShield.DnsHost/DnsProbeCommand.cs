using System.Net;
using System.Text.Json;
using QuietShield.Core.Dns;
using QuietShield.Windows.Dns;

namespace QuietShield.DnsHost;

internal static class DnsProbeCommand
{
    private static readonly JsonSerializerOptions JsonOptions = new() { WriteIndented = true };

    public static async Task<int> RunAsync(string[] args)
    {
        string? outputPath = null;
        try
        {
            var values = CommandLineValues.Parse(args);
            var serverText = values.Require("server");
            if (!IPAddress.TryParse(serverText, out var server) || !IPAddress.IsLoopback(server))
                throw new ArgumentException("The raw rehearsal probe permits only a numeric loopback server address.");
            var port = values.GetInt32("port", 53);
            if (port is < 1 or > 65535) throw new ArgumentOutOfRangeException(nameof(args), "The raw probe port is invalid.");
            var domain = values.Require("domain");
            var protocol = Enum.Parse<DnsRawProbeProtocol>(values.Require("protocol"), true);
            var expectedRcode = values.GetInt32("expected-rcode", 3);
            if (expectedRcode is < 0 or > 15) throw new ArgumentOutOfRangeException(nameof(args), "The expected DNS RCODE is invalid.");
            outputPath = values.RequirePath("output");

            var result = await DnsRawProbeClient.ProbeAsync(
                new IPEndPoint(server, port),
                domain,
                protocol,
                TimeSpan.FromSeconds(5),
                CancellationToken.None).ConfigureAwait(false);
            var passed = result.Validation.Succeeded &&
                         result.Validation.IsResponse &&
                         result.Validation.ExpectedTransactionId == result.Validation.ResponseTransactionId &&
                         (int)result.Validation.ResponseCode == expectedRcode &&
                         string.Equals(result.Validation.NormalizedQuestionName, DnsRehearsalPolicyEvaluator.BlockedTestDomain, StringComparison.Ordinal) &&
                         string.Equals(result.NormalizedQueryName, DnsRehearsalPolicyEvaluator.BlockedTestDomain, StringComparison.Ordinal);
            WriteJson(outputPath, new
            {
                schemaVersion = 1,
                productMarker = "QuietShield",
                purpose = "DnsRehearsalRawProbe",
                protocol = result.Protocol.ToString(),
                queriedName = result.NormalizedQueryName,
                responseQuestionName = result.Validation.NormalizedQuestionName,
                expectedTransactionId = result.Validation.ExpectedTransactionId,
                responseTransactionId = result.Validation.ResponseTransactionId,
                isResponse = result.Validation.IsResponse,
                responseCode = (int)result.Validation.ResponseCode,
                responseCodeName = result.Validation.ResponseCode.ToString(),
                responseLength = result.ResponseLength,
                validationSucceeded = result.Validation.Succeeded,
                passed,
                status = result.Validation.Status
            });
            return passed ? 0 : 1;
        }
        catch (Exception exception) when (exception is ArgumentException or IOException or InvalidOperationException or System.Net.Sockets.SocketException or OperationCanceledException)
        {
            if (!string.IsNullOrWhiteSpace(outputPath))
                WriteJson(outputPath, new { schemaVersion = 1, productMarker = "QuietShield", purpose = "DnsRehearsalRawProbe", passed = false, error = exception.Message });
            Console.Error.WriteLine(exception.Message);
            return 2;
        }
    }

    private static void WriteJson(string path, object value)
    {
        Directory.CreateDirectory(Path.GetDirectoryName(path) ?? throw new InvalidOperationException("A raw-probe output directory is required."));
        var temporary = path + ".tmp";
        File.WriteAllText(temporary, JsonSerializer.Serialize(value, JsonOptions));
        File.Move(temporary, path, true);
    }
}
