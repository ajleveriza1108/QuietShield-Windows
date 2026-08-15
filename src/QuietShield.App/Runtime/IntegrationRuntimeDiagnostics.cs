using System.Globalization;
using System.IO;
using System.Security;
using System.Text;

namespace QuietShield.App.Runtime;

internal static class IntegrationRuntimeDiagnostics
{
    private static readonly object Gate = new();

    internal static string LogPath { get; } = Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
        "QuietShield",
        "Diagnostics",
        "integration1-runtime.log");

    internal static void WriteMessage(string area, string message)
    {
        WriteCore(area, message);
    }

    internal static void WriteException(
        string area,
        string message,
        Exception exception)
    {
        ArgumentNullException.ThrowIfNull(exception);

        WriteCore(
            area,
            message +
            Environment.NewLine +
            exception);
    }

    private static void WriteCore(string area, string message)
    {
        var safeArea = string.IsNullOrWhiteSpace(area) ? "Runtime" : area.Trim();
        var safeMessage = string.IsNullOrWhiteSpace(message) ? "No detail." : message.Trim();

        var entry =
            DateTimeOffset.Now.ToString("O", CultureInfo.InvariantCulture) +
            " [" +
            safeArea +
            "] " +
            safeMessage +
            Environment.NewLine +
            Environment.NewLine;

        try
        {
            var directory = Path.GetDirectoryName(LogPath);
            if (!string.IsNullOrWhiteSpace(directory))
            {
                Directory.CreateDirectory(directory);
            }

            lock (Gate)
            {
                File.AppendAllText(
                    LogPath,
                    entry,
                    new UTF8Encoding(encoderShouldEmitUTF8Identifier: false));
            }
        }
        catch (IOException)
        {
        }
        catch (UnauthorizedAccessException)
        {
        }
        catch (SecurityException)
        {
        }
        catch (NotSupportedException)
        {
        }
    }
}
