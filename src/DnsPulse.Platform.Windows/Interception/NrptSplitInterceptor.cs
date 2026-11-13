using System.Net;
using DnsPulse.Platform.Windows.Contracts;
using DnsPulse.Platform.Windows.Networking;

namespace DnsPulse.Platform.Windows.Interception;

/// <summary>
/// Intercepts only designated split-DNS domain namespaces via Windows NRPT rules under <c>DnsPolicyConfig</c>.
/// </summary>
public sealed class NrptSplitInterceptor : IDnsInterceptor
{
    /// <inheritdoc />
    public InterceptionMode Mode => InterceptionMode.SplitNrpt;

    /// <inheritdoc />
    public Task ActivateAsync(
        IPAddress localDnsIp,
        int dnsPort,
        IReadOnlyList<string> splitDomains,
        CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(localDnsIp);
        ArgumentNullException.ThrowIfNull(splitDomains);
        ct.ThrowIfCancellationRequested();

        NrptPolicyManager.ApplySplitRules(localDnsIp, dnsPort, splitDomains);
        return Task.CompletedTask;
    }

    /// <inheritdoc />
    public Task DeactivateAsync(CancellationToken ct = default)
    {
        ct.ThrowIfCancellationRequested();
        NrptPolicyManager.RemoveAllPulseNrptRules();
        return Task.CompletedTask;
    }
}
