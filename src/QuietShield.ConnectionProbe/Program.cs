using System.Diagnostics;
using System.Globalization;
using System.Net;
using System.Net.Sockets;
using System.Text.Json;

namespace QuietShield.ConnectionProbe;

public static class Program
{
    public const int ConnectionSucceeded = 0;
    public const int ConnectionBlockedOrTimedOut = 10;
    public const int InvalidArguments = 20;
    public const int InternalError = 30;

    public static async Task<int> Main(string[] args)
    {
        if (!TryParse(args, out var address, out var port, out var timeout))
        {
            Console.Error.WriteLine("Usage: QuietShield.ConnectionProbe <literal-ip-address> <tcp-port> <timeout-milliseconds>");
            return InvalidArguments;
        }

        var started = DateTimeOffset.UtcNow;
        var stopwatch = Stopwatch.StartNew();
        var result = "InternalError";
        try
        {
            using var client = new TcpClient(address!.AddressFamily);
            using var cancellation = new CancellationTokenSource(timeout);
            await client.ConnectAsync(address, port, cancellation.Token).ConfigureAwait(false);
            result = "Connected";
            return ConnectionSucceeded;
        }
        catch (Exception exception) when (exception is SocketException or OperationCanceledException or TimeoutException)
        {
            result = "BlockedOrTimedOut";
            return ConnectionBlockedOrTimedOut;
        }
        catch
        {
            return InternalError;
        }
        finally
        {
            stopwatch.Stop();
            Console.WriteLine(JsonSerializer.Serialize(new
            {
                timestampUtc = started,
                destinationIp = address!.ToString(),
                port,
                durationMilliseconds = stopwatch.ElapsedMilliseconds,
                result
            }));
        }
    }

    private static bool TryParse(string[] args, out IPAddress? address, out int port, out TimeSpan timeout)
    {
        address = null;
        port = 0;
        timeout = TimeSpan.Zero;
        if (args.Length != 3 || !IPAddress.TryParse(args[0], out address) ||
            !int.TryParse(args[1], NumberStyles.None, CultureInfo.InvariantCulture, out port) || port is < 1 or > 65535 ||
            !int.TryParse(args[2], NumberStyles.None, CultureInfo.InvariantCulture, out var timeoutMilliseconds) ||
            timeoutMilliseconds is < 100 or > 120_000)
        {
            return false;
        }
        timeout = TimeSpan.FromMilliseconds(timeoutMilliseconds);
        return true;
    }
}
