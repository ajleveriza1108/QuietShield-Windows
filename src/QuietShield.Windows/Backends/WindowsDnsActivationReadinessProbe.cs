// QuietShield Backend Pack 1-4 R1
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;

namespace QuietShield.Windows.Backends;

public sealed record DnsActivationReadiness(
    bool Ipv4LoopbackPort53Available,
    bool Ipv6LoopbackPort53Available,
    bool LoopbackDnsAlreadyConfigured,
    bool SystemDnsActivationAllowed,
    IReadOnlyList<string> Blockers);

public static class WindowsDnsActivationReadinessProbe
{
    public static DnsActivationReadiness Probe()
    {
        var blockers = new List<string>();

        var ipv4Available = CanBind(IPAddress.Loopback, 53, AddressFamily.InterNetwork);
        var ipv6Available = Socket.OSSupportsIPv6 &&
                            CanBind(IPAddress.IPv6Loopback, 53, AddressFamily.InterNetworkV6);

        if (!ipv4Available)
        {
            blockers.Add("IPv4 loopback UDP port 53 is unavailable.");
        }

        if (Socket.OSSupportsIPv6 && !ipv6Available)
        {
            blockers.Add("IPv6 loopback UDP port 53 is unavailable.");
        }
        var loopbackConfigured = NetworkInterface
            .GetAllNetworkInterfaces()
            .Any(item =>
            {
                try
                {
                    return item.GetIPProperties()
                        .DnsAddresses
                        .Any(IPAddress.IsLoopback);
                }
                catch (NetworkInformationException)
                {
                    return false;
                }
            });

        if (loopbackConfigured)
        {
            blockers.Add("At least one Windows adapter already reports a loopback DNS server.");
        }

        // Intentionally remains false until the previously identified Phase 5
        // loopback activation blocker is explicitly resolved and revalidated.
        blockers.Add(
            "System DNS activation remains safety-gated until the Phase 5 loopback blocker is resolved and revalidated.");

        return new(
            ipv4Available,
            ipv6Available,
            loopbackConfigured,
            false,
            blockers);
    }

    private static bool CanBind(
        IPAddress address,
        int port,
        AddressFamily family)
    {
        Socket? socket = null;
        try
        {
            socket = new Socket(family, SocketType.Dgram, ProtocolType.Udp)
            {
                ExclusiveAddressUse = true
            };

            socket.Bind(new IPEndPoint(address, port));
            return true;
        }
        catch (SocketException)
        {
            return false;
        }
        finally
        {
            socket?.Dispose();
        }
    }
}
