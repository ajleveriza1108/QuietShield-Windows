// QuietShield Backend Integration 06 R1
using System.Security.Cryptography;
using QuietShield.Core.FinalBackends;

namespace QuietShield.Core.IntegrationWave;

public sealed class ParentChildRuntimeCoordinator
{
    private readonly byte[] _integrityKey;
    private ChildProtectionPolicy? _policy;

    public ParentChildRuntimeCoordinator(ReadOnlySpan<byte> integrityKey)
    {
        if (integrityKey.Length < 32)
            throw new ArgumentException("At least 256 bits of policy integrity key are required.", nameof(integrityKey));

        _integrityKey = integrityKey.ToArray();
    }

    public bool HasPolicy => _policy is not null;

    public void SetPolicy(ChildProtectionPolicy policy)
    {
        ArgumentNullException.ThrowIfNull(policy);
        _policy = policy;
    }

    public ChildAccessDecision Evaluate(ChildAccessRequest request)
    {
        ArgumentNullException.ThrowIfNull(request);

        if (_policy is null)
        {
            return new(
                true,
                "No child policy is configured.",
                true,
                true,
                true);
        }

        return ParentChildPolicyEngine.Evaluate(_policy, request);
    }

    public SignedChildPolicyEnvelope ExportProtectedPolicy()
    {
        if (_policy is null)
            throw new InvalidOperationException("No child policy is configured.");

        return ChildPolicyIntegrity.Protect(_policy, _integrityKey);
    }

    public void ImportProtectedPolicy(SignedChildPolicyEnvelope envelope)
    {
        ArgumentNullException.ThrowIfNull(envelope);
        _policy = ChildPolicyIntegrity.Unprotect(envelope, _integrityKey);
    }

    public static byte[] CreateIntegrityKey() =>
        RandomNumberGenerator.GetBytes(32);
}
