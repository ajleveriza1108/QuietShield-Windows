using System.Globalization;
using System.Text.Json;

namespace QuietShield.App.ViewModels;

#pragma warning disable CA1822 // WPF DataContext binding requires instance properties here.

public sealed partial class MainViewModel
{
    private const string DashboardBlockingCounterMarkerR364 =
        "QuietShield.Dashboard.BlockingCounters.R3.6.4";

    public string AdsBlockedTodayR364 =>
        ReadBlockingSnapshotR364().AdsBlocked.ToString(
            CultureInfo.InvariantCulture);

    public string TrackersBlockedTodayR364 =>
        ReadBlockingSnapshotR364().TrackersBlocked.ToString(
            CultureInfo.InvariantCulture);

    public string AdsBlockedStatusR364 =>
        ReadBlockingSnapshotR364().Status;

    public string TrackersBlockedStatusR364 =>
        ReadBlockingSnapshotR364().Status;

    private static DashboardBlockingSnapshotR364 ReadBlockingSnapshotR364()
    {
        var telemetryPath =
            System.IO.Path.Combine(
                Environment.GetFolderPath(
                    Environment.SpecialFolder.LocalApplicationData),
                "QuietShield",
                "Telemetry",
                "blocking-stats-today.json");

        if (!System.IO.File.Exists(telemetryPath))
        {
            return new DashboardBlockingSnapshotR364(
                0,
                0,
                "Blocking telemetry not active yet");
        }

        try
        {
            using var document =
                JsonDocument.Parse(
                    System.IO.File.ReadAllText(telemetryPath));

            var root =
                document.RootElement;

            var ads =
                ReadNonNegativeInt64R364(
                    root,
                    "adsBlocked");

            var trackers =
                ReadNonNegativeInt64R364(
                    root,
                    "trackersBlocked");

            if (root.TryGetProperty(
                    "dateLocal",
                    out var dateNode) &&
                dateNode.ValueKind == JsonValueKind.String)
            {
                var dateText =
                    dateNode.GetString();

                if (!string.Equals(
                        dateText,
                        DateTime.Now.ToString(
                            "yyyy-MM-dd",
                            CultureInfo.InvariantCulture),
                        StringComparison.Ordinal))
                {
                    return new DashboardBlockingSnapshotR364(
                        0,
                        0,
                        "No verified block events today");
                }
            }

            return new DashboardBlockingSnapshotR364(
                ads,
                trackers,
                "Verified local block events today");
        }
        catch
        {
            return new DashboardBlockingSnapshotR364(
                0,
                0,
                "Blocking telemetry unavailable");
        }
    }

    private static long ReadNonNegativeInt64R364(
        JsonElement root,
        string propertyName)
    {
        if (!root.TryGetProperty(
                propertyName,
                out var node) ||
            !node.TryGetInt64(
                out var value))
        {
            return 0;
        }

        return Math.Max(
            0,
            value);
    }

    private readonly record struct DashboardBlockingSnapshotR364(
        long AdsBlocked,
        long TrackersBlocked,
        string Status);
}
#pragma warning restore CA1822
