// QuietShield Backend Pack 5-8 R1
using System.ComponentModel;
using System.Diagnostics;

namespace QuietShield.Windows.FinalBackends;

public sealed record ChildProcessSnapshot(
    int ProcessId,
    string ProcessName,
    string? ExecutablePath);

public static class WindowsChildSessionProbe
{
    public static List<ChildProcessSnapshot> CaptureProcesses()
    {
        var results = new List<ChildProcessSnapshot>();

        foreach (var process in Process.GetProcesses())
        {
            using (process)
            {
                string? path = null;
                try
                {
                    path = process.MainModule?.FileName;
                }
                catch (Win32Exception)
                {
                }
                catch (InvalidOperationException)
                {
                }
                catch (NotSupportedException)
                {
                }

                results.Add(new(
                    process.Id,
                    process.ProcessName,
                    path));
            }
        }

        results.Sort(static (left, right) =>
            string.Compare(left.ProcessName, right.ProcessName, StringComparison.OrdinalIgnoreCase));

        return results;
    }
}
