using System.Diagnostics;
using System.Text.Json;
using QuietShield.Core.ServiceFoundation;

namespace QuietShield.Service;

public sealed class PowerShellPersistentFirewallBackend : IPersistentFirewallBackend
{
    private sealed record ScriptResult(string Status, bool Present, PersistentFirewallRuleSnapshot? Rule);

    private readonly ServiceActivationConfiguration _activation;
    private readonly PersistentFirewallTransactionStore _transactions;

    public PowerShellPersistentFirewallBackend(ServiceActivationConfiguration activation, PersistentFirewallTransactionStore transactions)
    {
        _activation = activation;
        _transactions = transactions;
    }

    public bool IsRealWindowsModifier => OperatingSystem.IsWindows() &&
        System.Security.Principal.WindowsIdentity.GetCurrent().IsSystem;

    public async Task<PersistentFirewallRuleSnapshot?> GetExactAsync(string ruleName, CancellationToken cancellationToken)
    {
        var result = await InvokeAsync(["-Operation", "Query", "-RuleName", ruleName], cancellationToken).ConfigureAwait(false);
        return result.Present ? result.Rule ?? throw new InvalidDataException("The exact-rule query omitted its rule snapshot.") : null;
    }

    public async Task ApplyBlockedAsync(PersistentFirewallTransaction transaction, CancellationToken cancellationToken) =>
        _ = await InvokeTransactionAsync("Blocked", transaction, cancellationToken).ConfigureAwait(false);

    public async Task ApplyAllowedOnAllAsync(PersistentFirewallTransaction transaction, CancellationToken cancellationToken) =>
        _ = await InvokeTransactionAsync("AllowedOnAll", transaction, cancellationToken).ConfigureAwait(false);

    public async Task RestoreAsync(PersistentFirewallTransaction transaction, CancellationToken cancellationToken) =>
        _ = await InvokeTransactionAsync("Restore", transaction, cancellationToken).ConfigureAwait(false);

    private Task<ScriptResult> InvokeTransactionAsync(string operation, PersistentFirewallTransaction transaction, CancellationToken cancellationToken) =>
        InvokeAsync(["-Operation", operation, "-TransactionPath", _transactions.GetPath(transaction.TransactionId), "-ApprovedServiceEnforcement"], cancellationToken);

    private async Task<ScriptResult> InvokeAsync(IReadOnlyList<string> arguments, CancellationToken cancellationToken)
    {
        if (!IsRealWindowsModifier) throw new UnauthorizedAccessException("The real Firewall backend is restricted to the LocalSystem Windows service identity.");
        var start = new ProcessStartInfo
        {
            FileName = "powershell.exe",
            UseShellExecute = false,
            CreateNoWindow = true,
            RedirectStandardOutput = true,
            RedirectStandardError = true
        };
        start.ArgumentList.Add("-NoProfile");
        start.ArgumentList.Add("-NonInteractive");
        start.ArgumentList.Add("-ExecutionPolicy");
        start.ArgumentList.Add("Bypass");
        start.ArgumentList.Add("-File");
        start.ArgumentList.Add(_activation.EnforcementScriptPath);
        foreach (var argument in arguments) start.ArgumentList.Add(argument);
        using var process = Process.Start(start) ?? throw new InvalidOperationException("The exact Firewall policy helper could not start.");
        var outputTask = process.StandardOutput.ReadToEndAsync(cancellationToken);
        var errorTask = process.StandardError.ReadToEndAsync(cancellationToken);
        if (!process.WaitForExit(30_000))
        {
            try { process.Kill(entireProcessTree: true); }
            catch (InvalidOperationException) { }
            throw new TimeoutException($"The exact Firewall policy helper did not exit within 30 seconds. Process ID: {process.Id}.");
        }
        await process.WaitForExitAsync(cancellationToken).ConfigureAwait(false);
        var output = await outputTask.ConfigureAwait(false);
        var error = await errorTask.ConfigureAwait(false);
        if (process.ExitCode != 0) throw new InvalidOperationException($"The exact Firewall policy helper failed with exit code {process.ExitCode}: {error.Trim()}");
        try
        {
            return JsonSerializer.Deserialize<ScriptResult>(output, ServiceMessageSerializer.Options)
                   ?? throw new InvalidDataException("The exact Firewall policy helper returned an empty result.");
        }
        catch (JsonException exception) { throw new InvalidDataException("The exact Firewall policy helper returned malformed JSON.", exception); }
    }
}
