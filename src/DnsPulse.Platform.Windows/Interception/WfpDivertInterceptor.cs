using System.Globalization;
using System.Net;
using DnsPulse.Platform.Windows.Contracts;

namespace DnsPulse.Platform.Windows.Interception;

/// <summary>
/// Optional WFP/WinDivert interception adapter that automatically blocks activation when anti-cheat drivers are active.
/// </summary>
public sealed class WfpDivertInterceptor : IDnsInterceptor
{
    private readonly Func<(bool IsAntiCheatActive, IReadOnlyList<string> DetectedNames)> _antiCheatDetector;

    /// <summary>
    /// Initializes a new <see cref="WfpDivertInterceptor"/> using live <see cref="AntiCheatGuard"/> process detection.
    /// </summary>
    public WfpDivertInterceptor()
        : this(AntiCheatGuard.DetectActiveAntiCheat)
    {
    }

    /// <summary>
    /// Initializes a new <see cref="WfpDivertInterceptor"/> with a custom anti-cheat detector delegate.
    /// </summary>
    public WfpDivertInterceptor(Func<(bool IsAntiCheatActive, IReadOnlyList<string> DetectedNames)> antiCheatDetector)
    {
        ArgumentNullException.ThrowIfNull(antiCheatDetector);
        _antiCheatDetector = antiCheatDetector;
    }

    /// <inheritdoc />
    public InterceptionMode Mode => InterceptionMode.WfpDivertPlugin;

    /// <summary>
    /// Gets a value indicating whether activation was paused/blocked due to active anti-cheat software.
    /// </summary>
    public bool IsPausedForAntiCheat { get; private set; }

    /// <summary>
    /// Gets the anti-cheat process names that caused activation to block.
    /// </summary>
    public IReadOnlyList<string> BlockedByAntiCheatNames { get; private set; } = [];

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

        (bool isAntiCheatActive, IReadOnlyList<string> detectedNames) = _antiCheatDetector();
        if (isAntiCheatActive)
        {
            IsPausedForAntiCheat = true;
            BlockedByAntiCheatNames = detectedNames;
            throw new InvalidOperationException(
                string.Create(
                    CultureInfo.InvariantCulture,
                    $"WFP/WinDivert interception paused safely because anti-cheat software is active: {string.Join(", ", detectedNames)}."));
        }

        IsPausedForAntiCheat = false;
        BlockedByAntiCheatNames = [];

        string pluginPath = Path.Combine(AppContext.BaseDirectory, "WinDivert.dll");
        if (!File.Exists(pluginPath))
        {
            throw new FileNotFoundException(
                "Optional WinDivert plugin binary (WinDivert.dll) is not installed in the application directory.",
                pluginPath);
        }

        throw new PlatformNotSupportedException("WinDivert packet-diversion driver initialization is provided by the external plugin.");
    }

    /// <inheritdoc />
    public Task DeactivateAsync(CancellationToken ct = default)
    {
        ct.ThrowIfCancellationRequested();
        IsPausedForAntiCheat = false;
        BlockedByAntiCheatNames = [];
        return Task.CompletedTask;
    }
}
