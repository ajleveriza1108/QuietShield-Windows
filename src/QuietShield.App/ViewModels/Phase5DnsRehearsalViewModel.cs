namespace QuietShield.App.ViewModels;

public sealed partial class MainViewModel
{
    private string _dnsRehearsalReadiness = "Read-only readiness discovery pending.";
    private string _dnsRehearsalActiveAdapter = "Pending";
    private string _dnsRehearsalPort53 = "Pending";
    private string _dnsRehearsalBackup = "Not created";
    private string _dnsRehearsalWatchdog = "Pending";
    private string _dnsRehearsalLastResult = "No rehearsal result available.";

    public string DnsRehearsalReadiness { get => _dnsRehearsalReadiness; private set => SetField(ref _dnsRehearsalReadiness, value); }
    public string DnsRehearsalActiveAdapter { get => _dnsRehearsalActiveAdapter; private set => SetField(ref _dnsRehearsalActiveAdapter, value); }
    public string DnsRehearsalPort53 { get => _dnsRehearsalPort53; private set => SetField(ref _dnsRehearsalPort53, value); }
    public string DnsRehearsalBackup { get => _dnsRehearsalBackup; private set => SetField(ref _dnsRehearsalBackup, value); }
    public string DnsRehearsalWatchdog { get => _dnsRehearsalWatchdog; private set => SetField(ref _dnsRehearsalWatchdog, value); }
    public string DnsRehearsalLastResult { get => _dnsRehearsalLastResult; private set => SetField(ref _dnsRehearsalLastResult, value); }

    private async Task InitializeDnsRehearsalReadinessAsync(CancellationToken cancellationToken)
    {
        var readiness = await _dnsRehearsalReadinessDiscovery.DiscoverAsync(cancellationToken).ConfigureAwait(true);
        DnsRehearsalReadiness = readiness.Readiness;
        DnsRehearsalActiveAdapter = readiness.ActiveAdapter;
        DnsRehearsalPort53 = readiness.Port53Availability;
        DnsRehearsalBackup = readiness.OriginalDnsBackupStatus;
        DnsRehearsalWatchdog = readiness.WatchdogReadiness;
        DnsRehearsalLastResult = readiness.LastRehearsalResult;
    }
}
