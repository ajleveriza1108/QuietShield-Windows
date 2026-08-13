// QuietShield Backend Pack 1-4 R1
using System.ComponentModel;
using System.Diagnostics;
using System.Net;
using System.Net.NetworkInformation;
using System.Runtime.InteropServices;
using QuietShield.Core.Backends;

namespace QuietShield.Windows.Backends;

public sealed class WindowsNetworkTelemetrySource : INetworkTelemetrySource
{
    private const int AfInet = 2;
    private const uint ErrorInsufficientBuffer = 122;

    public NetworkTelemetrySnapshot Capture()
    {
        var connections = new List<NetworkConnectionSample>();
        connections.AddRange(ReadTcpV4());
        connections.AddRange(ReadUdpV4());

        var interfaces = NetworkInterface
            .GetAllNetworkInterfaces()
            .Where(item => item.NetworkInterfaceType != NetworkInterfaceType.Loopback)
            .Select(CreateInterfaceSample)
            .OrderBy(item => item.Name, StringComparer.OrdinalIgnoreCase)
            .ToArray();

        return new(
            DateTimeOffset.UtcNow,
            connections,
            interfaces);
    }

    private static NetworkInterfaceSample CreateInterfaceSample(NetworkInterface item)
    {
        long bytesReceived = 0;
        long bytesSent = 0;
        long packetsReceived = 0;
        long packetsSent = 0;

        try
        {
            var stats = item.GetIPv4Statistics();
            bytesReceived = stats.BytesReceived;
            bytesSent = stats.BytesSent;
            packetsReceived = stats.UnicastPacketsReceived;
            packetsSent = stats.UnicastPacketsSent;
        }
        catch (NetworkInformationException)
        {
            // A transient/disconnected adapter may not expose counters.
        }

        return new(
            item.Id,
            item.Name,
            item.Description,
            item.NetworkInterfaceType.ToString(),
            item.OperationalStatus.ToString(),
            bytesReceived,
            bytesSent,
            packetsReceived,
            packetsSent);
    }

    private static List<NetworkConnectionSample> ReadTcpV4()
    {
        var size = 0;
        var result = GetExtendedTcpTable(
            IntPtr.Zero,
            ref size,
            true,
            AfInet,
            TcpTableClass.TcpTableOwnerPidAll,
            0);

        if (result != ErrorInsufficientBuffer && result != 0)
        {
            throw new Win32Exception((int)result);
        }

        var buffer = Marshal.AllocHGlobal(size);
        try
        {
            result = GetExtendedTcpTable(
                buffer,
                ref size,
                true,
                AfInet,
                TcpTableClass.TcpTableOwnerPidAll,
                0);

            if (result != 0)
            {
                throw new Win32Exception((int)result);
            }

            var count = Marshal.ReadInt32(buffer);
            var rowSize = Marshal.SizeOf<MibTcpRowOwnerPid>();
            var current = IntPtr.Add(buffer, sizeof(int));
            var list = new List<NetworkConnectionSample>(Math.Max(0, count));

            for (var i = 0; i < count; i++)
            {
                var row = Marshal.PtrToStructure<MibTcpRowOwnerPid>(current);
                var pid = unchecked((int)row.OwningPid);

                list.Add(new(
                    NetworkTransportProtocol.Tcp,
                    AddressFromUInt32(row.LocalAddress),
                    DecodePort(row.LocalPort),
                    AddressFromUInt32(row.RemoteAddress),
                    DecodePort(row.RemotePort),
                    pid,
                    TryGetProcessName(pid),
                    ((TcpState)row.State).ToString()));

                current = IntPtr.Add(current, rowSize);
            }

            return list;
        }
        finally
        {
            Marshal.FreeHGlobal(buffer);
        }
    }

    private static List<NetworkConnectionSample> ReadUdpV4()
    {
        var size = 0;
        var result = GetExtendedUdpTable(
            IntPtr.Zero,
            ref size,
            true,
            AfInet,
            UdpTableClass.UdpTableOwnerPid,
            0);

        if (result != ErrorInsufficientBuffer && result != 0)
        {
            throw new Win32Exception((int)result);
        }

        var buffer = Marshal.AllocHGlobal(size);
        try
        {
            result = GetExtendedUdpTable(
                buffer,
                ref size,
                true,
                AfInet,
                UdpTableClass.UdpTableOwnerPid,
                0);

            if (result != 0)
            {
                throw new Win32Exception((int)result);
            }

            var count = Marshal.ReadInt32(buffer);
            var rowSize = Marshal.SizeOf<MibUdpRowOwnerPid>();
            var current = IntPtr.Add(buffer, sizeof(int));
            var list = new List<NetworkConnectionSample>(Math.Max(0, count));

            for (var i = 0; i < count; i++)
            {
                var row = Marshal.PtrToStructure<MibUdpRowOwnerPid>(current);
                var pid = unchecked((int)row.OwningPid);

                list.Add(new(
                    NetworkTransportProtocol.Udp,
                    AddressFromUInt32(row.LocalAddress),
                    DecodePort(row.LocalPort),
                    string.Empty,
                    0,
                    pid,
                    TryGetProcessName(pid),
                    "Listening"));

                current = IntPtr.Add(current, rowSize);
            }

            return list;
        }
        finally
        {
            Marshal.FreeHGlobal(buffer);
        }
    }

    private static string AddressFromUInt32(uint raw) =>
        new IPAddress(BitConverter.GetBytes(raw)).ToString();

    private static int DecodePort(uint raw)
    {
        var bytes = BitConverter.GetBytes(raw);
        return (bytes[0] << 8) | bytes[1];
    }

    private static string TryGetProcessName(int processId)
    {
        if (processId <= 0)
        {
            return string.Empty;
        }

        try
        {
            using var process = Process.GetProcessById(processId);
            return process.ProcessName;
        }
        catch
        {
            return string.Empty;
        }
    }

    [DllImport("iphlpapi.dll", SetLastError = true)]
    private static extern uint GetExtendedTcpTable(
        IntPtr tcpTable,
        ref int outBufferLength,
        bool order,
        int ipVersion,
        TcpTableClass tableClass,
        uint reserved);

    [DllImport("iphlpapi.dll", SetLastError = true)]
    private static extern uint GetExtendedUdpTable(
        IntPtr udpTable,
        ref int outBufferLength,
        bool order,
        int ipVersion,
        UdpTableClass tableClass,
        uint reserved);

    private enum TcpTableClass
    {
        TcpTableBasicListener,
        TcpTableBasicConnections,
        TcpTableBasicAll,
        TcpTableOwnerPidListener,
        TcpTableOwnerPidConnections,
        TcpTableOwnerPidAll
    }

    private enum UdpTableClass
    {
        UdpTableBasic,
        UdpTableOwnerPid,
        UdpTableOwnerModule
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct MibTcpRowOwnerPid
    {
        public uint State;
        public uint LocalAddress;
        public uint LocalPort;
        public uint RemoteAddress;
        public uint RemotePort;
        public uint OwningPid;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct MibUdpRowOwnerPid
    {
        public uint LocalAddress;
        public uint LocalPort;
        public uint OwningPid;
    }
}
