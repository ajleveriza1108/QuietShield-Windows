using System.Globalization;
using System.IO;
using QuietShield.Core.ServiceFoundation;

namespace QuietShield.App.ViewModels;

public sealed partial class MainViewModel
{
    private static NamedPipeQuietShieldServiceClient CreateProductionServiceClientR3543() =>
        new(
            QuietShieldServiceProtocol.ProductionPipeName,
            TimeSpan.FromSeconds(5),
            false);

    private static void WriteProtectionIpcDiagnosticR3543(
        string message)
    {
        try
        {
            var directory =
                Path.Combine(
                    Environment.GetFolderPath(
                        Environment.SpecialFolder.LocalApplicationData),
                    "QuietShield",
                    "Diagnostics");

            Directory.CreateDirectory(directory);

            var path =
                Path.Combine(
                    directory,
                    "protection-ipc.log");

            var line =
                DateTimeOffset.Now.ToString(
                    "yyyy-MM-dd HH:mm:ss.fff zzz",
                    CultureInfo.InvariantCulture) +
                " | " +
                message +
                Environment.NewLine;

            File.AppendAllText(
                path,
                line);
        }
        catch
        {
            // Diagnostics must never make protection controls fail.
        }
    }
}
