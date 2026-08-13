// QuietShield Backend Pack 5-8 R1
using System.Security.Cryptography;
using System.Text;

namespace QuietShield.Windows.FinalBackends;

public enum FileRiskLevel
{
    Low = 0,
    Caution = 1,
    High = 2
}

public sealed record FileSafetyReport(
    string FullPath,
    long Length,
    string Sha256,
    string Extension,
    FileRiskLevel Risk,
    bool HasPortableExecutableHeader,
    bool HasMarkOfTheWeb,
    string? MarkOfTheWebZone,
    IReadOnlyList<string> Signals);

public static class WindowsFileSafetyScanner
{
    private static readonly char[] LineSeparators = ['\r', '\n'];

    private static readonly HashSet<string> HighRiskExtensions =
        new(StringComparer.OrdinalIgnoreCase)
        {
            ".exe", ".msi", ".msix", ".appx", ".scr", ".com", ".dll",
            ".bat", ".cmd", ".ps1", ".vbs", ".js", ".jse", ".wsf"
        };

    private static readonly HashSet<string> MacroExtensions =
        new(StringComparer.OrdinalIgnoreCase)
        {
            ".docm", ".xlsm", ".pptm"
        };

    public static async Task<FileSafetyReport> ScanAsync(
        string path,
        CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(path);

        var fullPath = Path.GetFullPath(path);
        var info = new FileInfo(fullPath);
        if (!info.Exists)
        {
            throw new FileNotFoundException("File safety target was not found.", fullPath);
        }

        string sha256;
        bool portableExecutable;

        await using (var stream = new FileStream(
            fullPath,
            FileMode.Open,
            FileAccess.Read,
            FileShare.Read,
            bufferSize: 128 * 1024,
            FileOptions.Asynchronous | FileOptions.SequentialScan))
        {
            var prefix = new byte[2];
            var read = await stream.ReadAsync(prefix, cancellationToken).ConfigureAwait(false);
            portableExecutable = read == 2 && prefix[0] == (byte)'M' && prefix[1] == (byte)'Z';

            stream.Position = 0;
            var hash = await SHA256.HashDataAsync(stream, cancellationToken).ConfigureAwait(false);
            sha256 = Convert.ToHexString(hash);
        }

        var extension = info.Extension;
        var signals = new List<string>();
        var risk = FileRiskLevel.Low;

        if (HighRiskExtensions.Contains(extension))
        {
            signals.Add("Executable or script-capable file extension.");
            risk = FileRiskLevel.High;
        }
        else if (MacroExtensions.Contains(extension))
        {
            signals.Add("Macro-enabled Office document extension.");
            risk = FileRiskLevel.Caution;
        }

        if (portableExecutable)
        {
            signals.Add("Portable Executable MZ header detected.");
            risk = FileRiskLevel.High;
        }

        var mark = TryReadMarkOfTheWeb(fullPath);
        if (mark.HasMark)
        {
            signals.Add("Mark-of-the-Web Zone.Identifier detected.");
            if (risk == FileRiskLevel.Low)
            {
                risk = FileRiskLevel.Caution;
            }
        }

        if (info.Length == 0)
        {
            signals.Add("File is empty.");
            if (risk == FileRiskLevel.Low)
            {
                risk = FileRiskLevel.Caution;
            }
        }

        return new(
            fullPath,
            info.Length,
            sha256,
            extension,
            risk,
            portableExecutable,
            mark.HasMark,
            mark.Zone,
            signals);
    }

    private static (bool HasMark, string? Zone) TryReadMarkOfTheWeb(string fullPath)
    {
        var adsPath = fullPath + ":Zone.Identifier";

        try
        {
            using var stream = new FileStream(
                adsPath,
                FileMode.Open,
                FileAccess.Read,
                FileShare.ReadWrite);

            using var reader = new StreamReader(
                stream,
                Encoding.UTF8,
                detectEncodingFromByteOrderMarks: true);

            var content = reader.ReadToEnd();
            var zone = content
                .Split(LineSeparators, StringSplitOptions.RemoveEmptyEntries)
                .FirstOrDefault(static line =>
                    line.StartsWith("ZoneId=", StringComparison.OrdinalIgnoreCase));

            return (true, zone);
        }
        catch (FileNotFoundException)
        {
            return (false, null);
        }
        catch (DirectoryNotFoundException)
        {
            return (false, null);
        }
        catch (IOException)
        {
            return (false, null);
        }
        catch (UnauthorizedAccessException)
        {
            return (false, null);
        }
    }
}
