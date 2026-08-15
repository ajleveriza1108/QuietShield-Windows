// QuietShield Backend Integration 05 R1
using System.Diagnostics;
using QuietShield.Core.IntegrationWave;

namespace QuietShield.Windows.IntegrationWave;

public static class WindowsProgramSnapshot
{
    public static IReadOnlyList<ProgramObservation> Capture()
    {
        var capturedAt = DateTimeOffset.UtcNow;
        var result = new List<ProgramObservation>();

        foreach (var process in Process.GetProcesses())
        {
            using (process)
            {
                try
                {
                    var name = process.ProcessName;
                    var identity = "process:" + name.ToLowerInvariant();
                    result.Add(new(identity, name, false, capturedAt));
                }
                catch (InvalidOperationException)
                {
                }
                catch (System.ComponentModel.Win32Exception)
                {
                }
                catch (NotSupportedException)
                {
                }
            }
        }

        return result
            .GroupBy(static item => item.StableIdentity, StringComparer.Ordinal)
            .Select(static group => group.First())
            .OrderBy(static item => item.DisplayName, StringComparer.CurrentCultureIgnoreCase)
            .ToArray();
    }
}
