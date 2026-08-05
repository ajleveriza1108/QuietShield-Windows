using System.Collections.ObjectModel;
using System.Globalization;
using System.Windows.Input;
using QuietShield.Core.Dns;

namespace QuietShield.App.ViewModels;

public sealed partial class MainViewModel
{
    private static readonly string[] RequiredSafetyDomains = { "recovery.quietshield.invalid", "updates.quietshield.invalid" };
    private DnsProtectionMode _selectedDnsProtectionMode = DnsProtectionMode.Standard;
    private string _dnsTestDomain = "malware.example.test";
    private string _dnsDecision = "Not simulated";
    private string _dnsCategory = "None";
    private string _dnsReason = "Enter a bare domain and run a local simulation.";
    private string _dnsMatchedRule = "None";
    private string _protectionListStatus = "Not initialized";
    private string _lastKnownGoodListStatus = "Not initialized";
    private string _customDnsSearch = string.Empty;
    private string _customDnsDomain = string.Empty;
    private string _customDnsNotes = string.Empty;
    private CustomDomainListKind _selectedCustomListKind = CustomDomainListKind.Blocklist;
    private DnsRuleMatchKind _selectedCustomMatchKind = DnsRuleMatchKind.DomainAndSubdomains;
    private bool _customDnsParentProtected;
    private CustomDomainEntry? _selectedCustomDnsEntry;
    private string _customDnsStatus = "Custom entries are in-memory simulation data only.";

    public ObservableCollection<CustomDomainEntry> CustomDnsEntries { get; } = new();
    public IReadOnlyList<DnsProtectionMode> DnsProtectionModes { get; } = Enum.GetValues<DnsProtectionMode>();
    public IReadOnlyList<CustomDomainListKind> CustomDomainListKinds { get; } = Enum.GetValues<CustomDomainListKind>();
    public IReadOnlyList<DnsRuleMatchKind> DnsRuleMatchKinds { get; } = Enum.GetValues<DnsRuleMatchKind>();
    public ICommand SimulateDnsCommand { get; private set; } = null!;
    public ICommand AddCustomDnsCommand { get; private set; } = null!;
    public ICommand EditCustomDnsCommand { get; private set; } = null!;
    public ICommand RemoveCustomDnsCommand { get; private set; } = null!;
    public ICommand ClearDnsDecisionCacheCommand { get; private set; } = null!;

    public DnsProtectionMode SelectedDnsProtectionMode { get => _selectedDnsProtectionMode; set => SetField(ref _selectedDnsProtectionMode, value); }
    public string DnsTestDomain { get => _dnsTestDomain; set => SetField(ref _dnsTestDomain, value); }
    public string DnsDecision { get => _dnsDecision; private set => SetField(ref _dnsDecision, value); }
    public string DnsCategory { get => _dnsCategory; private set => SetField(ref _dnsCategory, value); }
    public string DnsReason { get => _dnsReason; private set => SetField(ref _dnsReason, value); }
    public string DnsMatchedRule { get => _dnsMatchedRule; private set => SetField(ref _dnsMatchedRule, value); }
    public string ProtectionListStatus { get => _protectionListStatus; private set => SetField(ref _protectionListStatus, value); }
    public string LastKnownGoodListStatus { get => _lastKnownGoodListStatus; private set => SetField(ref _lastKnownGoodListStatus, value); }
    public string CustomDnsSearch { get => _customDnsSearch; set { if (SetField(ref _customDnsSearch, value)) _ = RefreshCustomDnsEntriesAsync(CancellationToken.None); } }
    public string CustomDnsDomain { get => _customDnsDomain; set => SetField(ref _customDnsDomain, value); }
    public string CustomDnsNotes { get => _customDnsNotes; set => SetField(ref _customDnsNotes, value); }
    public CustomDomainListKind SelectedCustomListKind { get => _selectedCustomListKind; set => SetField(ref _selectedCustomListKind, value); }
    public DnsRuleMatchKind SelectedCustomMatchKind { get => _selectedCustomMatchKind; set => SetField(ref _selectedCustomMatchKind, value); }
    public bool CustomDnsParentProtected { get => _customDnsParentProtected; set => SetField(ref _customDnsParentProtected, value); }
    public string CustomDnsStatus { get => _customDnsStatus; private set => SetField(ref _customDnsStatus, value); }
    public string DnsNoWindowsChangeStatement { get; } = "No Windows DNS setting has been changed";

    public CustomDomainEntry? SelectedCustomDnsEntry
    {
        get => _selectedCustomDnsEntry;
        set
        {
            if (!SetField(ref _selectedCustomDnsEntry, value) || value is null) return;
            CustomDnsDomain = value.DomainPattern;
            CustomDnsNotes = value.Notes ?? string.Empty;
            SelectedCustomListKind = value.ListKind;
            SelectedCustomMatchKind = value.MatchKind;
            CustomDnsParentProtected = value.ParentProtected;
            RaiseDnsCommandStates();
        }
    }

    private void InitializeDnsCommands()
    {
        SimulateDnsCommand = new AsyncRelayCommand(SimulateDnsAsync, () => !IsRefreshing);
        AddCustomDnsCommand = new AsyncRelayCommand(AddCustomDnsAsync, () => !IsRefreshing);
        EditCustomDnsCommand = new AsyncRelayCommand(EditCustomDnsAsync, () => !IsRefreshing && SelectedCustomDnsEntry is not null);
        RemoveCustomDnsCommand = new AsyncRelayCommand(RemoveCustomDnsAsync, () => !IsRefreshing && SelectedCustomDnsEntry is not null);
        ClearDnsDecisionCacheCommand = new AsyncRelayCommand(ClearDnsDecisionCacheAsync, () => !IsRefreshing);
    }

    private async Task InitializeDnsFoundationAsync(CancellationToken cancellationToken)
    {
        var sample = NonProductionSampleProtectionLists.Create(DateTimeOffset.UtcNow);
        var activation = await _dnsListActivator.ActivateAsync(sample, cancellationToken).ConfigureAwait(true);
        ProtectionListStatus = activation.Succeeded
            ? $"{NonProductionSampleProtectionLists.Warning}; version {activation.ActiveSnapshot!.Metadata.Version}; expires {activation.ActiveSnapshot.Metadata.ExpiresAtUtc:u}"
            : activation.Status;
        LastKnownGoodListStatus = _dnsListStore.LastKnownGoodSnapshot is null
            ? "No last-known-good list"
            : $"Version {_dnsListStore.LastKnownGoodSnapshot.Metadata.Version} verified and available";
        await RefreshCustomDnsEntriesAsync(cancellationToken).ConfigureAwait(true);
    }

    private async Task SimulateDnsAsync()
    {
        var normalized = DomainNormalizer.NormalizeDomain(DnsTestDomain);
        if (!normalized.IsValid || normalized.NormalizedValue is null)
        {
            ShowDnsResult(DnsPolicyEngine.Evaluate(new DnsPolicyRequest(
                DnsTestDomain, SelectedDnsProtectionMode, new HashSet<QuietShield.Core.Dns.DnsCategory>(), _dnsListStore.ActiveSnapshot,
                Array.Empty<CustomDomainEntry>(), RequiredSafetyDomains, DateTimeOffset.UtcNow)));
            return;
        }

        var key = new DnsDecisionCacheKey(normalized.NormalizedValue, SelectedDnsProtectionMode);
        var cached = await _dnsDecisionCache.TryGetAsync(key, CancellationToken.None).ConfigureAwait(true);
        if (cached is not null)
        {
            ShowDnsResult(cached.Result, " (safe in-memory cache)");
            return;
        }

        var custom = await _customDnsLists.GetAllAsync(CancellationToken.None).ConfigureAwait(true);
        var request = new DnsPolicyRequest(
            normalized.NormalizedValue,
            SelectedDnsProtectionMode,
            new HashSet<QuietShield.Core.Dns.DnsCategory>(),
            _dnsListStore.ActiveSnapshot,
            custom,
            RequiredSafetyDomains,
            DateTimeOffset.UtcNow);
        var result = DnsPolicyEngine.Evaluate(request);
        var kind = result.Decision == QuietShield.Core.Dns.DnsDecision.Allow ? DnsCacheEntryKind.Positive : DnsCacheEntryKind.Negative;
        await _dnsDecisionCache.SetAsync(key, result, kind, TimeSpan.FromMinutes(5), CancellationToken.None).ConfigureAwait(true);
        ShowDnsResult(result);
    }

    private void ShowDnsResult(DnsPolicyResult result, string suffix = "")
    {
        DnsDecision = result.Decision + suffix;
        DnsCategory = result.Category?.ToString() ?? "None";
        DnsReason = result.Reason;
        DnsMatchedRule = result.MatchedRule ?? "None";
    }

    private async Task AddCustomDnsAsync()
    {
        var result = await _customDnsLists.AddAsync(CreateDraft(), CancellationToken.None).ConfigureAwait(true);
        CustomDnsStatus = result.Status;
        if (result.Succeeded) await AfterCustomDnsChangeAsync(result.Entry).ConfigureAwait(true);
    }

    private async Task EditCustomDnsAsync()
    {
        if (SelectedCustomDnsEntry is null) return;
        var result = await _customDnsLists.EditAsync(SelectedCustomDnsEntry.Id, CreateDraft(), CancellationToken.None).ConfigureAwait(true);
        CustomDnsStatus = result.Status;
        if (result.Succeeded) await AfterCustomDnsChangeAsync(result.Entry).ConfigureAwait(true);
    }

    private async Task RemoveCustomDnsAsync()
    {
        if (SelectedCustomDnsEntry is null) return;
        var result = await _customDnsLists.RemoveAsync(SelectedCustomDnsEntry.Id, CancellationToken.None).ConfigureAwait(true);
        CustomDnsStatus = result.Status;
        if (result.Succeeded)
        {
            SelectedCustomDnsEntry = null;
            await AfterCustomDnsChangeAsync(null).ConfigureAwait(true);
        }
    }

    private async Task AfterCustomDnsChangeAsync(CustomDomainEntry? selected)
    {
        await _dnsDecisionCache.ClearAsync(CancellationToken.None).ConfigureAwait(true);
        await RefreshCustomDnsEntriesAsync(CancellationToken.None).ConfigureAwait(true);
        SelectedCustomDnsEntry = selected is null ? null : CustomDnsEntries.FirstOrDefault(entry => entry.Id == selected.Id);
    }

    private async Task RefreshCustomDnsEntriesAsync(CancellationToken cancellationToken)
    {
        var entries = await _customDnsLists.SearchAsync(CustomDnsSearch, cancellationToken).ConfigureAwait(true);
        CustomDnsEntries.Clear();
        foreach (var entry in entries) CustomDnsEntries.Add(entry);
        RaiseDnsCommandStates();
    }

    private async Task ClearDnsDecisionCacheAsync()
    {
        await _dnsDecisionCache.ClearAsync(CancellationToken.None).ConfigureAwait(true);
        CustomDnsStatus = "The non-persistent DNS decision cache was cleared.";
    }

    private CustomDomainEntryDraft CreateDraft() => new(
        CustomDnsDomain,
        SelectedCustomMatchKind,
        SelectedCustomListKind,
        CustomDnsNotes,
        CustomDnsParentProtected);

    private void RaiseDnsCommandStates()
    {
        foreach (var command in new[] { SimulateDnsCommand, AddCustomDnsCommand, EditCustomDnsCommand, RemoveCustomDnsCommand, ClearDnsDecisionCacheCommand }.OfType<AsyncRelayCommand>())
        {
            command.RaiseCanExecuteChanged();
        }
    }
}
