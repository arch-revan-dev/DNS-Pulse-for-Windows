using System.ComponentModel;
using System.Diagnostics;

namespace DnsPulse.Platform.Windows.Interception;

/// <summary>
/// Detects active kernel-level anti-cheat services and tray monitors so WinDivert/WFP interception can avoid conflicts.
/// </summary>
public static class AntiCheatGuard
{
    private static readonly string[] KnownAntiCheatNames =
    [
        "vgtray",
        "vgc",
        "EasyAntiCheat",
        "EasyAntiCheat_EOS",
        "FACEITClient",
        "faceitservice",
        "BEService"
    ];

    private static readonly HashSet<string> KnownAntiCheatSet = new(KnownAntiCheatNames, StringComparer.OrdinalIgnoreCase);

    /// <summary>
    /// Canonical list of known anti-cheat process names monitored by <see cref="AntiCheatGuard"/>.
    /// </summary>
    public static IReadOnlyList<string> MonitoredProcessNames => KnownAntiCheatNames;

    /// <summary>
    /// Scans running Windows processes for known anti-cheat software.
    /// </summary>
    public static (bool IsAntiCheatActive, IReadOnlyList<string> DetectedNames) DetectActiveAntiCheat()
    {
        Process[] processes = Process.GetProcesses();
        List<string> processNames = new(processes.Length);

        foreach (Process process in processes)
        {
            using (process)
            {
                try
                {
                    if (!string.IsNullOrWhiteSpace(process.ProcessName))
                    {
                        processNames.Add(process.ProcessName);
                    }
                }
                catch (InvalidOperationException)
                {
                }
                catch (Win32Exception)
                {
                }
            }
        }

        return EvaluateProcessNames(processNames);
    }

    /// <summary>
    /// Evaluates a sequence of process names against known anti-cheat signatures.
    /// </summary>
    public static (bool IsAntiCheatActive, IReadOnlyList<string> DetectedNames) EvaluateProcessNames(
        IEnumerable<string> runningProcessNames)
    {
        ArgumentNullException.ThrowIfNull(runningProcessNames);

        HashSet<string> detectedSet = new(StringComparer.OrdinalIgnoreCase);
        List<string> detected = [];

        foreach (string rawName in runningProcessNames)
        {
            if (string.IsNullOrWhiteSpace(rawName))
            {
                continue;
            }

            string normalized = Path.GetFileNameWithoutExtension(rawName.Trim());
            if (KnownAntiCheatSet.Contains(normalized) && detectedSet.Add(normalized))
            {
                detected.Add(GetCanonicalName(normalized));
            }
        }

        return (detected.Count > 0, detected);
    }

    private static string GetCanonicalName(string normalized)
    {
        foreach (string known in KnownAntiCheatNames)
        {
            if (string.Equals(known, normalized, StringComparison.OrdinalIgnoreCase))
            {
                return known;
            }
        }

        return normalized;
    }
}
