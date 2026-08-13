// QuietShield Backend Pack 5-8 R1
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text;
using Microsoft.Win32;

namespace QuietShield.Windows.FinalBackends;

public static class WindowsOpaqueDeviceIdentity
{
    public static string GetCurrentUserDeviceId()
    {
        if (!OperatingSystem.IsWindows())
        {
            throw new PlatformNotSupportedException("Windows opaque device identity requires Windows.");
        }

        var machineGuid = ReadMachineGuid();

        using var identity = WindowsIdentity.GetCurrent();
        var sid = identity.User?.Value
                  ?? throw new InvalidOperationException("Current Windows SID is unavailable.");

        var canonical = "QuietShield|Windows|DeviceIdentity|v1|" + machineGuid + "|" + sid;
        var hash = SHA256.HashData(Encoding.UTF8.GetBytes(canonical));
        return Convert.ToHexString(hash).ToLowerInvariant();
    }

    private static string ReadMachineGuid()
    {
        using var baseKey = RegistryKey.OpenBaseKey(
            RegistryHive.LocalMachine,
            RegistryView.Registry64);

        using var key = baseKey.OpenSubKey(
            @"SOFTWARE\Microsoft\Cryptography",
            writable: false);

        var value = key?.GetValue("MachineGuid") as string;
        if (string.IsNullOrWhiteSpace(value))
        {
            throw new InvalidOperationException("Windows MachineGuid is unavailable.");
        }

        return value.Trim();
    }
}
