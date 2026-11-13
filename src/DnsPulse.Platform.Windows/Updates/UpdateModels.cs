using System.Diagnostics.CodeAnalysis;

namespace DnsPulse.Platform.Windows.Updates;

/// <summary>
/// Release track used when querying GitHub Releases.
/// </summary>
public enum UpdateChannel
{
    Stable = 0,
    Beta = 1
}

/// <summary>
/// Metadata and asset URLs for a GitHub release of DNS Pulse.
/// </summary>
[SuppressMessage("Design", "CA1054:URI-like parameters should not be strings", Justification = "GitHub release URLs are stored and serialized as strings.")]
[SuppressMessage("Design", "CA1056:URI-like properties should not be strings", Justification = "GitHub release URLs are stored and serialized as strings.")]
public sealed record ReleaseInfo(
    string TagName,
    string VersionText,
    Version ParsedVersion,
    bool IsPrerelease,
    string ReleaseNotes,
    string? SetupExeUrl,
    string? PortableExeUrl,
    string? Sha256SumsUrl,
    string? Sha256SumsSigUrl,
    string HtmlUrl,
    string? SetupApiUrl = null,
    string? PortableApiUrl = null,
    string? Sha256ApiUrl = null,
    string? Sha256SigApiUrl = null);

/// <summary>
/// Result of checking GitHub Releases for a newer application version.
/// </summary>
public sealed record UpdateCheckResult(
    bool UpdateAvailable,
    Version CurrentVersion,
    ReleaseInfo? LatestRelease,
    string? ErrorMessage = null);

/// <summary>
/// Verification and staging outcome for a downloaded update artifact.
/// </summary>
public sealed record VerifiedUpdateResult(
    bool Verified,
    string PreparedFilePath,
    bool IsInstaller,
    string Sha256Hex,
    bool SignatureVerified,
    bool AuthenticodePresent,
    string? AuthenticodeSubject,
    string Summary);
