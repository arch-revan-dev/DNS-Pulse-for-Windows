using DnsPulse.Platform.Windows.Contracts;
using DnsPulse.Platform.Windows.Recovery;
using Serilog;

namespace DnsPulse.App.Services;

/// <summary>
/// Parsed command-line launch flags supported by <c>DnsPulse.exe</c>.
/// </summary>
public sealed record CliLaunchOptions(
    bool RestoreNetwork = false,
    bool Autostart = false,
    bool Minimized = false,
    bool ApplyTunnel = false,
    string? ConnectServerId = null);

/// <summary>
/// Parses and handles command-line launch arguments (<c>--restore-network</c>, <c>--autostart</c>,
/// <c>--minimized</c>, <c>--apply-tunnel</c>, <c>--connect-id &lt;id&gt;</c>).
/// </summary>
public static class CliArgumentHandler
{
    /// <summary>
    /// Parses command-line arguments into <see cref="CliLaunchOptions"/>.
    /// </summary>
    public static CliLaunchOptions Parse(IReadOnlyList<string>? args)
    {
        if (args is null || args.Count == 0)
        {
            return new CliLaunchOptions();
        }

        bool restoreNetwork = false;
        bool autostart = false;
        bool minimized = false;
        bool applyTunnel = false;
        string? connectServerId = null;

        for (int i = 0; i < args.Count; i++)
        {
            string? token = args[i];
            if (string.IsNullOrWhiteSpace(token))
            {
                continue;
            }

            string trimmed = token.Trim();
            if (string.Equals(trimmed, "--restore-network", StringComparison.OrdinalIgnoreCase))
            {
                restoreNetwork = true;
            }
            else if (string.Equals(trimmed, "--autostart", StringComparison.OrdinalIgnoreCase))
            {
                autostart = true;
            }
            else if (string.Equals(trimmed, "--minimized", StringComparison.OrdinalIgnoreCase))
            {
                minimized = true;
            }
            else if (string.Equals(trimmed, "--apply-tunnel", StringComparison.OrdinalIgnoreCase))
            {
                applyTunnel = true;
            }
            else if (string.Equals(trimmed, "--connect-id", StringComparison.OrdinalIgnoreCase))
            {
                if (i + 1 < args.Count && !string.IsNullOrWhiteSpace(args[i + 1]) && !args[i + 1].StartsWith("--", StringComparison.Ordinal))
                {
                    connectServerId = args[i + 1].Trim();
                    i++;
                }
            }
            else if (trimmed.StartsWith("--connect-id=", StringComparison.OrdinalIgnoreCase))
            {
                string value = trimmed["--connect-id=".Length..].Trim();
                if (!string.IsNullOrWhiteSpace(value))
                {
                    connectServerId = value;
                }
            }
        }

        return new CliLaunchOptions(
            RestoreNetwork: restoreNetwork,
            Autostart: autostart,
            Minimized: minimized,
            ApplyTunnel: applyTunnel,
            ConnectServerId: connectServerId);
    }

    /// <summary>
    /// Executes early-exit CLI actions (such as <c>--restore-network</c>) before the WPF shell starts.
    /// Returns an exit code (e.g., <c>0</c>) if the process should exit immediately, or <see langword="null"/> to continue normal startup.
    /// </summary>
    public static async Task<int?> TryHandleEarlyExitAsync(
        CliLaunchOptions options,
        NetworkSnapshotJournal? journal = null,
        Func<PrePulseNetworkSnapshot?, NetworkRestoredResult>? nativeRestoreExecutor = null,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(options);

        if (!options.RestoreNetwork)
        {
            return null;
        }

        NetworkSnapshotJournal effectiveJournal = journal ?? new NetworkSnapshotJournal();
        Func<PrePulseNetworkSnapshot?, NetworkRestoredResult> restoreFunc =
            nativeRestoreExecutor ?? NetworkSnapshotJournal.ExecuteNativeRestore;

        NetworkRestoredResult result = await effectiveJournal.RecoverIfDirtyAsync(
            (snapshot, _) => Task.FromResult(restoreFunc(snapshot)),
            cancellationToken).ConfigureAwait(false);

        if (!result.HadDirtyState)
        {
            result = restoreFunc(null);
        }

        Log.Information(
            "CLI --restore-network completed (HadDirtyState={HadDirtyState}, AdaptersRestored={AdaptersRestored}, PoliciesCleaned={PoliciesCleaned}): {Summary}",
            result.HadDirtyState,
            result.AdaptersRestored,
            result.PoliciesCleaned,
            result.Summary);

        return 0;
    }
}
