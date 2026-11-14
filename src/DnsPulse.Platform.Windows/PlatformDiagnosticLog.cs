using System.Diagnostics.CodeAnalysis;

namespace DnsPulse.Platform.Windows;

/// <summary>
/// Lightweight zero-dependency diagnostic logging bridge allowing platform helpers to emit
/// non-PII diagnostic events into the host application's or service's structured logger.
/// </summary>
public static class PlatformDiagnosticLog
{
    private static Action<string, Exception?>? s_sink;

    /// <summary>
    /// Attaches the host structured logging sink (for example Serilog or Microsoft.Extensions.Logging).
    /// </summary>
    public static void Configure(Action<string, Exception?>? sink)
    {
        Volatile.Write(ref s_sink, sink);
    }

    /// <summary>
    /// Emits a diagnostic message to the configured host sink, if present.
    /// </summary>
    [SuppressMessage("Design", "CA1031:Do not catch general exception types", Justification = "Diagnostic sink invocation must never disrupt core platform operations.")]
    public static void Write(string message, Exception? exception = null)
    {
        if (string.IsNullOrWhiteSpace(message))
        {
            return;
        }

        Action<string, Exception?>? sink = Volatile.Read(ref s_sink);
        if (sink is null)
        {
            return;
        }

        try
        {
            sink(message, exception);
        }
        catch (Exception)
        {
            // Never propagate logging sink failures.
        }
    }
}
