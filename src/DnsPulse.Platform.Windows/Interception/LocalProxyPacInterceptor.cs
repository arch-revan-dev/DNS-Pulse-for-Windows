using System.Diagnostics.CodeAnalysis;
using System.Globalization;
using System.Net;
using System.Net.Sockets;
using DnsPulse.Platform.Windows.Contracts;

namespace DnsPulse.Platform.Windows.Interception;

/// <summary>
/// Configures unprivileged user-level WinINet Auto-PAC proxying without modifying system-wide adapter DNS settings.
/// </summary>
public sealed class LocalProxyPacInterceptor : IDnsInterceptor
{
    private const int DefaultPacPort = 8080;

    private readonly string? _configuredPacUrl;
    private string? _priorAutoConfigUrl;
    private bool _isActive;

    /// <summary>
    /// Initializes a new <see cref="LocalProxyPacInterceptor"/>.
    /// </summary>
    [SuppressMessage("Design", "CA1054:URI-like parameters should not be strings", Justification = "Matches requested public constructor signature for WinINet AutoConfigURL.")]
    public LocalProxyPacInterceptor(string? pacUrl = null)
    {
        _configuredPacUrl = string.IsNullOrWhiteSpace(pacUrl) ? null : pacUrl.Trim();
    }

    /// <inheritdoc />
    public InterceptionMode Mode => InterceptionMode.LocalProxyPacOnly;

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

        string targetPacUrl = _configuredPacUrl ?? BuildDefaultPacUrl(localDnsIp, DefaultPacPort);
        _priorAutoConfigUrl = WinInetProxyManager.SetAutoConfigUrl(targetPacUrl);
        _isActive = true;

        return Task.CompletedTask;
    }

    /// <inheritdoc />
    public Task DeactivateAsync(CancellationToken ct = default)
    {
        ct.ThrowIfCancellationRequested();

        if (_isActive)
        {
            WinInetProxyManager.RestoreAutoConfigUrl(_priorAutoConfigUrl);
            _priorAutoConfigUrl = null;
            _isActive = false;
        }

        return Task.CompletedTask;
    }

    private static string BuildDefaultPacUrl(IPAddress localIp, int pacPort)
    {
        return localIp.AddressFamily == AddressFamily.InterNetworkV6
            ? string.Create(CultureInfo.InvariantCulture, $"http://[{localIp}]:{pacPort}/proxy.pac")
            : string.Create(CultureInfo.InvariantCulture, $"http://{localIp}:{pacPort}/proxy.pac");
    }
}
