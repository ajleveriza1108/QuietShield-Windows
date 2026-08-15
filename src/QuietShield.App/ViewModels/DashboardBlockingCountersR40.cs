// QuietShield Backend Runtime Completion R4.0
using System.Text.Json;
using System.IO;
using System.Windows.Threading;
using QuietShield.Core.ServiceFoundation;

namespace QuietShield.App.ViewModels;

public sealed partial class MainViewModel
{
    private DispatcherTimer? _blockingCounterTimerR40;
    private string _adsBlockedTodayR40 = "0";
    private string _trackersBlockedTodayR40 = "0";
    private string _blockingCounterStatusR40 = "Waiting for QuietShield backend telemetry.";

    public string AdsBlockedTodayR40
    {
        get => _adsBlockedTodayR40;
        private set => SetField(ref _adsBlockedTodayR40, value);
    }

    public string TrackersBlockedTodayR40
    {
        get => _trackersBlockedTodayR40;
        private set => SetField(ref _trackersBlockedTodayR40, value);
    }

    public string AdsBlockedStatusR40 => _blockingCounterStatusR40;
    public string TrackersBlockedStatusR40 => _blockingCounterStatusR40;

    private void InitializeDashboardBlockingCountersR40()
    {
        if (_blockingCounterTimerR40 is not null)
            return;

        _blockingCounterTimerR40 = new DispatcherTimer(DispatcherPriority.Background)
        {
            Interval = TimeSpan.FromSeconds(2)
        };

        _blockingCounterTimerR40.Tick += OnBlockingCounterTimerR40;
        _blockingCounterTimerR40.Start();
        _ = RefreshDashboardBlockingCountersR40Async();
    }

    private void DisposeDashboardBlockingCountersR40()
    {
        if (_blockingCounterTimerR40 is null)
            return;

        _blockingCounterTimerR40.Stop();
        _blockingCounterTimerR40.Tick -= OnBlockingCounterTimerR40;
        _blockingCounterTimerR40 = null;
    }

    private async void OnBlockingCounterTimerR40(object? sender, EventArgs e)
    {
        await RefreshDashboardBlockingCountersR40Async().ConfigureAwait(true);
    }

    private async Task RefreshDashboardBlockingCountersR40Async()
    {
        try
        {
            var response =
                await _serviceClient.SendAsync(
                    ServiceMessageKind.GetProtectionStatistics,
                    null,
                    CancellationToken.None).ConfigureAwait(true);

            if (response.Status != ServiceResponseStatus.Ok)
            {
                SetBlockingCounterStatusR40("Protection telemetry is not active.");
                return;
            }

            var snapshot =
                response.Payload.Deserialize<ProtectionStatisticsSnapshotR40>(
                    ServiceMessageSerializer.Options);

            if (snapshot is null)
            {
                SetBlockingCounterStatusR40("Protection telemetry returned no snapshot.");
                return;
            }

            AdsBlockedTodayR40 =
                snapshot.AdsBlocked.ToString(System.Globalization.CultureInfo.InvariantCulture);

            TrackersBlockedTodayR40 =
                snapshot.TrackersBlocked.ToString(System.Globalization.CultureInfo.InvariantCulture);

            SetBlockingCounterStatusR40(snapshot.Status);
        }
        catch (Exception exception) when (
            exception is IOException or TimeoutException or
            InvalidDataException or JsonException or OperationCanceledException)
        {
            SetBlockingCounterStatusR40("Protection telemetry is unavailable.");
        }
    }

    private void SetBlockingCounterStatusR40(string value)
    {
        if (string.Equals(_blockingCounterStatusR40, value, StringComparison.Ordinal))
            return;

        _blockingCounterStatusR40 = value;
        OnPropertyChanged(nameof(AdsBlockedStatusR40));
        OnPropertyChanged(nameof(TrackersBlockedStatusR40));
    }
}
