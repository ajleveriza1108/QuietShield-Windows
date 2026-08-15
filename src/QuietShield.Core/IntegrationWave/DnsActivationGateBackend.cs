// QuietShield Backend Integration 03 R1
namespace QuietShield.Core.IntegrationWave;

public sealed record DnsActivationReadiness(
    bool KnownPhase5BlockerCleared,
    bool LocalProxyHealthy,
    bool AdapterSnapshotCaptured,
    bool RollbackValidated,
    bool ExplicitAdministratorApproval,
    bool ConflictingDnsProductDetected);

public sealed record DnsActivationDecision(
    bool EligibleForExplicitActivation,
    IReadOnlyList<string> BlockingReasons,
    bool AdapterMutationPerformed);

public static class DnsActivationSafetyGate
{
    public static DnsActivationDecision Evaluate(
        DnsActivationReadiness readiness)
    {
        ArgumentNullException.ThrowIfNull(readiness);

        var reasons = new List<string>();

        if (!readiness.KnownPhase5BlockerCleared)
            reasons.Add("Known Phase 5 system-DNS blocker is not cleared.");
        if (!readiness.LocalProxyHealthy)
            reasons.Add("Local DNS proxy is not healthy.");
        if (!readiness.AdapterSnapshotCaptured)
            reasons.Add("Adapter DNS snapshot is missing.");
        if (!readiness.RollbackValidated)
            reasons.Add("DNS rollback has not been validated.");
        if (!readiness.ExplicitAdministratorApproval)
            reasons.Add("Explicit administrator approval is missing.");
        if (readiness.ConflictingDnsProductDetected)
            reasons.Add("A conflicting DNS/VPN/security product was detected.");

        return new(
            reasons.Count == 0,
            reasons,
            AdapterMutationPerformed: false);
    }
}
