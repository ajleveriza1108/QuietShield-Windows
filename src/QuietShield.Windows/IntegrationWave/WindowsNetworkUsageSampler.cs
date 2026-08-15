// QuietShield Backend Integration 04 R1
using System.Net.NetworkInformation;
using QuietShield.Core.IntegrationWave;

namespace QuietShield.Windows.IntegrationWave;

public static class WindowsNetworkUsageSampler
{
    public static NetworkUsageSnapshot Capture()
    {
        long received = 0;
        long sent = 0;

        foreach (var adapter in NetworkInterface.GetAllNetworkInterfaces())
        {
            if (adapter.NetworkInterfaceType == NetworkInterfaceType.Loopback ||
                adapter.OperationalStatus != OperationalStatus.Up)
            {
                continue;
            }

            try
            {
                var stats = adapter.GetIPv4Statistics();
                received = checked(received + stats.BytesReceived);
                sent = checked(sent + stats.BytesSent);
            }
            catch (NetworkInformationException)
            {
            }
            catch (PlatformNotSupportedException)
            {
            }
            catch (OverflowException)
            {
            }
        }

        return new(DateTimeOffset.UtcNow, received, sent);
    }
}
