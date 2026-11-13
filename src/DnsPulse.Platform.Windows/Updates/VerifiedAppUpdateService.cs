using System.Collections.Immutable;
using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;
using System.Globalization;
using System.Net;
using System.Net.Http.Headers;
using System.Net.Sockets;
using System.Reflection;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;
using DnsPulse.Core.Cryptography;
using DnsPulse.Core.Security;
using DnsPulse.Engine.Contracts;

namespace DnsPulse.Platform.Windows.Updates;

/// <summary>
/// Queries GitHub Releases for <c>arch-revan-dev/DNS-Pulse-for-Windows</c> via an
/// <see cref="IBootstrapResolver"/>-backed <see cref="HttpClient"/> (with Windows system proxy fallback),
/// verifies <c>SHA256SUMS.txt</c> (and optional detached Ed25519 signature + Windows Authenticode),
/// and stages verified binaries for silent Inno Setup or portable replacement.
/// </summary>
public sealed class VerifiedAppUpdateService : IDisposable
{
    public const string RepoOwner = "arch-revan-dev";
    public const string RepoName = "DNS-Pulse-for-Windows";
    public const string SetupInstallerAssetName = "DNS-Pulse-win-x64-setup.exe";
    public const string PortableExecutableAssetName = "DnsPulse.exe";
    public const string Sha256SumsAssetName = "SHA256SUMS.txt";
    public const string Sha256SumsSigAssetName = "SHA256SUMS.txt.sig";
    public const string SilentInnoSetupArguments = "/VERYSILENT /SUPPRESSMSGBOXES /NORESTART";

    private const string ApiLatestUrl = $"https://api.github.com/repos/{RepoOwner}/{RepoName}/releases/latest";
    private const string ApiReleasesListUrl = $"https://api.github.com/repos/{RepoOwner}/{RepoName}/releases?per_page=10";
    private const string WebLatestUrl = $"https://github.com/{RepoOwner}/{RepoName}/releases/latest";
    private const int MaxManifestBytes = 1024 * 1024;
    private const int MaxSignatureBytes = 4096;

    private static readonly char[] VersionTrimChars = ['v', 'V'];

    private readonly ReadOnlyMemory<byte> _ed25519PublicKey;
    private readonly TimeSpan _requestTimeout;
    private readonly Version? _currentVersionOverride;
    private readonly SocketsHttpHandler? _ownedBootstrapCheckHandler;
    private readonly SocketsHttpHandler? _ownedBootstrapDownloadHandler;
    private readonly SocketsHttpHandler? _ownedSystemProxyCheckHandler;
    private readonly SocketsHttpHandler? _ownedSystemProxyDownloadHandler;
    private readonly HttpClient _bootstrapCheckClient;
    private readonly HttpClient _bootstrapDownloadClient;
    private readonly HttpClient _systemProxyCheckClient;
    private readonly HttpClient _systemProxyDownloadClient;
    private readonly HttpClient[] _checkClients;
    private readonly HttpClient[] _downloadClients;
    private bool _disposed;

    /// <summary>
    /// Initializes a new <see cref="VerifiedAppUpdateService"/> backed by <paramref name="bootstrapResolver"/>.
    /// </summary>
    /// <param name="bootstrapResolver">Encrypted-first bootstrap DNS resolver.</param>
    /// <param name="ed25519PublicKey">Optional 32-byte Ed25519 public key used to verify detached <c>SHA256SUMS.txt.sig</c> signatures.</param>
    /// <param name="requestTimeout">Optional timeout applied to release metadata requests.</param>
    public VerifiedAppUpdateService(
        IBootstrapResolver bootstrapResolver,
        ReadOnlyMemory<byte> ed25519PublicKey = default,
        TimeSpan? requestTimeout = null)
        : this(bootstrapResolver, customBootstrapHandler: null, customSystemProxyHandler: null, ed25519PublicKey, requestTimeout)
    {
        ArgumentNullException.ThrowIfNull(bootstrapResolver);
    }

    /// <summary>
    /// Initializes a new <see cref="VerifiedAppUpdateService"/> with optional custom HTTP message handlers (for DI or unit testing).
    /// </summary>
    public VerifiedAppUpdateService(
        IBootstrapResolver? bootstrapResolver,
        HttpMessageHandler? customBootstrapHandler,
        HttpMessageHandler? customSystemProxyHandler = null,
        ReadOnlyMemory<byte> ed25519PublicKey = default,
        TimeSpan? requestTimeout = null,
        Version? currentVersionOverride = null)
    {
        if (bootstrapResolver is null && customBootstrapHandler is null)
        {
            throw new ArgumentNullException(nameof(bootstrapResolver));
        }

        if (!ed25519PublicKey.IsEmpty && ed25519PublicKey.Length != 32)
        {
            throw new ArgumentException("Ed25519 public key must be exactly 32 bytes.", nameof(ed25519PublicKey));
        }

        _ed25519PublicKey = ed25519PublicKey;
        _requestTimeout = requestTimeout ?? TimeSpan.FromSeconds(15);
        _currentVersionOverride = currentVersionOverride;

        if (customBootstrapHandler is null)
        {
            _ownedBootstrapCheckHandler = CreateBootstrapSocketsHandler(bootstrapResolver!, allowAutoRedirect: false);
            _ownedBootstrapDownloadHandler = CreateBootstrapSocketsHandler(bootstrapResolver!, allowAutoRedirect: true);
            _bootstrapCheckClient = CreateConfiguredClient(_ownedBootstrapCheckHandler, _requestTimeout, acceptGitHubJson: true);
            _bootstrapDownloadClient = CreateConfiguredClient(_ownedBootstrapDownloadHandler, TimeSpan.FromMinutes(6), acceptGitHubJson: false);
        }
        else
        {
            _bootstrapCheckClient = CreateConfiguredClient(customBootstrapHandler, _requestTimeout, acceptGitHubJson: true);
            _bootstrapDownloadClient = CreateConfiguredClient(customBootstrapHandler, TimeSpan.FromMinutes(6), acceptGitHubJson: false);
        }

        if (customSystemProxyHandler is null)
        {
            _ownedSystemProxyCheckHandler = CreateSystemProxySocketsHandler(allowAutoRedirect: false);
            _ownedSystemProxyDownloadHandler = CreateSystemProxySocketsHandler(allowAutoRedirect: true);
            _systemProxyCheckClient = CreateConfiguredClient(_ownedSystemProxyCheckHandler, _requestTimeout, acceptGitHubJson: true);
            _systemProxyDownloadClient = CreateConfiguredClient(_ownedSystemProxyDownloadHandler, TimeSpan.FromMinutes(6), acceptGitHubJson: false);
        }
        else
        {
            _systemProxyCheckClient = CreateConfiguredClient(customSystemProxyHandler, _requestTimeout, acceptGitHubJson: true);
            _systemProxyDownloadClient = CreateConfiguredClient(customSystemProxyHandler, TimeSpan.FromMinutes(6), acceptGitHubJson: false);
        }

        _checkClients = [_bootstrapCheckClient, _systemProxyCheckClient];
        _downloadClients = [_bootstrapDownloadClient, _systemProxyDownloadClient];
    }

    /// <summary>
    /// Returns the running application's parsed semantic version.
    /// </summary>
    [SuppressMessage("Design", "CA1024:Use properties where appropriate", Justification = "Performs assembly reflection lookup.")]
    public static Version GetCurrentVersion()
    {
        Assembly? entry = Assembly.GetEntryAssembly();
        Assembly asm = entry is not null
            && (entry.GetName().Name?.StartsWith("DnsPulse", StringComparison.OrdinalIgnoreCase) ?? false)
            ? entry
            : typeof(VerifiedAppUpdateService).Assembly;
        string? infoVer = asm.GetCustomAttribute<AssemblyInformationalVersionAttribute>()?.InformationalVersion;
        if (!string.IsNullOrWhiteSpace(infoVer) && TryParseVersion(infoVer, out Version parsedInfo))
        {
            return parsedInfo;
        }

        Version? asmVer = asm.GetName().Version;
        if (asmVer is not null)
        {
            return new Version(asmVer.Major, Math.Max(0, asmVer.Minor), Math.Max(0, asmVer.Build));
        }

        return new Version(2, 0, 0);
    }

    /// <summary>
    /// Checks whether the application is running as an Inno Setup installation (<c>unins000.exe</c> present).
    /// </summary>
    public static bool IsInstalledEdition(string? exePath = null)
    {
        string? exe = exePath ?? Environment.ProcessPath;
        if (string.IsNullOrWhiteSpace(exe))
        {
            return false;
        }

        string? dir = Path.GetDirectoryName(exe);
        if (string.IsNullOrWhiteSpace(dir))
        {
            return false;
        }

        return File.Exists(Path.Combine(dir, "unins000.exe"));
    }

    /// <summary>
    /// Parses a version or release tag string (e.g., <c>v2.0.1-beta.1</c>) into a normalized <see cref="Version"/>.
    /// </summary>
    public static bool TryParseVersion(string? raw, out Version version)
    {
        version = new Version(0, 0, 0);
        if (string.IsNullOrWhiteSpace(raw))
        {
            return false;
        }

        string s = raw.Trim().TrimStart(VersionTrimChars);
        int plusIdx = s.IndexOf('+', StringComparison.Ordinal);
        if (plusIdx >= 0)
        {
            s = s[..plusIdx];
        }

        int dashIdx = s.IndexOf('-', StringComparison.Ordinal);
        if (dashIdx >= 0)
        {
            s = s[..dashIdx];
        }

        if (!Version.TryParse(s, out Version? parsed) || parsed is null)
        {
            return false;
        }

        version = parsed.Build < 0
            ? new Version(parsed.Major, Math.Max(0, parsed.Minor), 0)
            : parsed.Revision >= 0
                ? new Version(parsed.Major, parsed.Minor, parsed.Build, parsed.Revision)
                : new Version(parsed.Major, parsed.Minor, parsed.Build);
        return true;
    }

    /// <summary>
    /// Compares two <see cref="Version"/> instances treating missing build/revision components as zero.
    /// </summary>
    public static int CompareVersions(Version left, Version right)
    {
        ArgumentNullException.ThrowIfNull(left);
        ArgumentNullException.ThrowIfNull(right);

        int cmp = left.Major.CompareTo(right.Major);
        if (cmp != 0)
        {
            return cmp;
        }

        cmp = Math.Max(0, left.Minor).CompareTo(Math.Max(0, right.Minor));
        if (cmp != 0)
        {
            return cmp;
        }

        cmp = Math.Max(0, left.Build).CompareTo(Math.Max(0, right.Build));
        if (cmp != 0)
        {
            return cmp;
        }

        return Math.Max(0, left.Revision).CompareTo(Math.Max(0, right.Revision));
    }

    /// <summary>
    /// Parses a single GitHub Release JSON object into a <see cref="ReleaseInfo"/>.
    /// </summary>
    public static ReleaseInfo? ParseReleaseJson(string json)
    {
        if (string.IsNullOrWhiteSpace(json))
        {
            return null;
        }

        try
        {
            using JsonDocument doc = JsonDocument.Parse(json);
            if (doc.RootElement.ValueKind != JsonValueKind.Object)
            {
                return null;
            }

            return ParseReleaseElement(doc.RootElement);
        }
        catch (JsonException)
        {
            return null;
        }
    }

    /// <summary>
    /// Parses a GitHub Releases JSON array and selects the highest-version matching release for <paramref name="channel"/>.
    /// </summary>
    public static ReleaseInfo? ParseReleasesListJson(string json, UpdateChannel channel)
    {
        if (string.IsNullOrWhiteSpace(json))
        {
            return null;
        }

        try
        {
            using JsonDocument doc = JsonDocument.Parse(json);
            if (doc.RootElement.ValueKind != JsonValueKind.Array)
            {
                return doc.RootElement.ValueKind == JsonValueKind.Object
                    ? ParseReleaseElement(doc.RootElement)
                    : null;
            }

            ReleaseInfo? best = null;
            foreach (JsonElement element in doc.RootElement.EnumerateArray())
            {
                if (element.ValueKind != JsonValueKind.Object)
                {
                    continue;
                }

                if (element.TryGetProperty("draft", out JsonElement draftEl) && draftEl.ValueKind == JsonValueKind.True)
                {
                    continue;
                }

                ReleaseInfo? parsed = ParseReleaseElement(element);
                if (parsed is null)
                {
                    continue;
                }

                if (channel == UpdateChannel.Stable && parsed.IsPrerelease)
                {
                    continue;
                }

                if (best is null || IsCandidateNewerThan(parsed, best))
                {
                    best = parsed;
                }
            }

            return best;
        }
        catch (JsonException)
        {
            return null;
        }
    }

    /// <summary>
    /// Queries GitHub Releases for updates on the configured <paramref name="channel"/>.
    /// </summary>
    public async Task<UpdateCheckResult> CheckForUpdateAsync(
        UpdateChannel channel = UpdateChannel.Stable,
        string? githubToken = null,
        CancellationToken cancellationToken = default)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);

        Version current = _currentVersionOverride ?? GetCurrentVersion();
        ReleaseInfo? latest = null;
        int? lastApiStatus = null;
        string? transportError = null;
        string token = (githubToken ?? string.Empty).Trim();
        string endpointUrl = channel == UpdateChannel.Beta ? ApiReleasesListUrl : ApiLatestUrl;

        foreach (HttpClient client in _checkClients)
        {
            if (latest is not null || cancellationToken.IsCancellationRequested)
            {
                break;
            }

            try
            {
                using HttpRequestMessage req = new(HttpMethod.Get, endpointUrl);
                if (token.Length > 0)
                {
                    req.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);
                }

                using HttpResponseMessage resp = await client.SendAsync(req, cancellationToken).ConfigureAwait(false);
                lastApiStatus = (int)resp.StatusCode;
                if (resp.IsSuccessStatusCode)
                {
                    string json = await resp.Content.ReadAsStringAsync(cancellationToken).ConfigureAwait(false);
                    latest = channel == UpdateChannel.Beta
                        ? ParseReleasesListJson(json, channel)
                        : ParseReleaseJson(json);
                    if (latest is not null)
                    {
                        break;
                    }
                }
            }
            catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
            {
                throw;
            }
            catch (HttpRequestException ex)
            {
                transportError = ex.Message;
            }
            catch (IOException ex)
            {
                transportError = ex.Message;
            }
            catch (SocketException ex)
            {
                transportError = ex.Message;
            }
            catch (OperationCanceledException)
            {
                transportError = "Release check timed out.";
            }
        }

        int? webStatus = null;
        if (latest is null && channel == UpdateChannel.Stable)
        {
            foreach (HttpClient client in _checkClients)
            {
                if (latest is not null || cancellationToken.IsCancellationRequested)
                {
                    break;
                }

                try
                {
                    using HttpRequestMessage req = new(HttpMethod.Get, WebLatestUrl);
                    using HttpResponseMessage resp = await client.SendAsync(req, HttpCompletionOption.ResponseHeadersRead, cancellationToken).ConfigureAwait(false);
                    webStatus = (int)resp.StatusCode;
                    string loc = resp.Headers.Location?.ToString() ?? string.Empty;
                    const string marker = "/releases/tag/";
                    int idx = loc.IndexOf(marker, StringComparison.OrdinalIgnoreCase);
                    if (idx >= 0)
                    {
                        string tag = loc[(idx + marker.Length)..].Trim().TrimEnd('/');
                        if (TryParseVersion(tag, out Version ver))
                        {
                            string dlBase = string.Create(CultureInfo.InvariantCulture, $"https://github.com/{RepoOwner}/{RepoName}/releases/download/{tag}");
                            latest = new ReleaseInfo(
                                TagName: tag,
                                VersionText: tag.StartsWith('v') || tag.StartsWith('V') ? tag : string.Concat("v", tag),
                                ParsedVersion: ver,
                                IsPrerelease: tag.Contains('-', StringComparison.Ordinal),
                                ReleaseNotes: string.Empty,
                                SetupExeUrl: string.Concat(dlBase, "/", SetupInstallerAssetName),
                                PortableExeUrl: string.Concat(dlBase, "/", PortableExecutableAssetName),
                                Sha256SumsUrl: string.Concat(dlBase, "/", Sha256SumsAssetName),
                                Sha256SumsSigUrl: string.Concat(dlBase, "/", Sha256SumsSigAssetName),
                                HtmlUrl: string.Create(CultureInfo.InvariantCulture, $"https://github.com/{RepoOwner}/{RepoName}/releases/tag/{tag}"));
                        }
                    }
                }
                catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
                {
                    throw;
                }
                catch (HttpRequestException ex)
                {
                    transportError ??= ex.Message;
                }
                catch (IOException ex)
                {
                    transportError ??= ex.Message;
                }
                catch (SocketException ex)
                {
                    transportError ??= ex.Message;
                }
                catch (OperationCanceledException)
                {
                    transportError ??= "GitHub web redirect check timed out.";
                }
            }
        }

        string? errorMsg = null;
        if (latest is null)
        {
            int? code = lastApiStatus ?? webStatus;
            if (code is int statusCode)
            {
                errorMsg = statusCode switch
                {
                    404 => "Release or repository not found (HTTP 404). Configure a GitHub token if the repository is private.",
                    401 => "Invalid or expired GitHub token (HTTP 401).",
                    403 or 429 => "GitHub API rate limit exceeded (HTTP 403/429). Retry later or configure a GitHub token.",
                    _ => string.Create(CultureInfo.InvariantCulture, $"GitHub returned HTTP {statusCode} while checking for updates.")
                };
            }
            else
            {
                errorMsg = string.IsNullOrWhiteSpace(transportError)
                    ? "Unable to reach GitHub Releases."
                    : string.Create(CultureInfo.InvariantCulture, $"Network error contacting GitHub: {transportError}");
            }
        }

        bool available = latest is not null && CompareVersions(latest.ParsedVersion, current) > 0;
        return new UpdateCheckResult(available, current, latest, errorMsg);
    }

    /// <summary>
    /// Downloads the appropriate release binary, verifies <c>SHA256SUMS.txt</c> (via <see cref="SignedManifestVerifier"/>),
    /// checks optional detached Ed25519 signature and optional Windows Authenticode signature, and stages the verified file.
    /// Fails closed and deletes staged bytes if any cryptographic verification fails.
    /// </summary>
    [SuppressMessage("Globalization", "CA1308:Normalize strings to uppercase", Justification = "SHA-256 digests are canonically lowercase hex.")]
    public async Task<VerifiedUpdateResult> DownloadAndVerifyUpdateAsync(
        ReleaseInfo release,
        string? stagingRootDirectory = null,
        IProgress<(double Percent, string Status)>? progress = null,
        string? githubToken = null,
        bool requireSignature = false,
        CancellationToken cancellationToken = default)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        ArgumentNullException.ThrowIfNull(release);

        bool useInstaller = IsInstalledEdition() && (!string.IsNullOrWhiteSpace(release.SetupExeUrl) || !string.IsNullOrWhiteSpace(release.SetupApiUrl));
        string? assetUrl = useInstaller ? release.SetupExeUrl : (release.PortableExeUrl ?? release.SetupExeUrl);
        string? assetApiUrl = useInstaller ? release.SetupApiUrl : (release.PortableApiUrl ?? release.SetupApiUrl);
        if (string.IsNullOrWhiteSpace(assetUrl) && string.IsNullOrWhiteSpace(assetApiUrl))
        {
            throw new InvalidOperationException("Release contains neither a Windows x64 installer nor a portable executable.");
        }

        bool actuallyInstaller = useInstaller
            || (assetUrl ?? string.Empty).EndsWith(SetupInstallerAssetName, StringComparison.OrdinalIgnoreCase);
        string fileName = actuallyInstaller ? SetupInstallerAssetName : PortableExecutableAssetName;

        string safeTag = SanitizePathSegment(release.TagName);
        string rootDir = string.IsNullOrWhiteSpace(stagingRootDirectory)
            ? Path.Combine(Path.GetTempPath(), "DNS-Pulse-update")
            : Path.GetFullPath(stagingRootDirectory);
        string stageDir = Path.Combine(rootDir, safeTag);
        Directory.CreateDirectory(stageDir);

        string partPath = Path.Combine(stageDir, string.Concat(fileName, ".part"));
        string finalPath = Path.Combine(stageDir, fileName);

        progress?.Report((2, string.Create(CultureInfo.InvariantCulture, $"Downloading {release.VersionText}...")));

        try
        {
            using (HttpResponseMessage resp = await SendAssetDownloadAsync(assetUrl, assetApiUrl, githubToken, cancellationToken).ConfigureAwait(false))
            {
                long? totalBytes = resp.Content.Headers.ContentLength;
                await using Stream remoteStream = await resp.Content.ReadAsStreamAsync(cancellationToken).ConfigureAwait(false);
                await using FileStream localStream = new(
                    partPath,
                    FileMode.Create,
                    FileAccess.Write,
                    FileShare.None,
                    bufferSize: 81920,
                    FileOptions.Asynchronous | FileOptions.WriteThrough);

                byte[] buffer = new byte[81920];
                long downloaded = 0;
                long lastReportTicks = 0;

                while (true)
                {
                    int read = await remoteStream.ReadAsync(buffer, cancellationToken).ConfigureAwait(false);
                    if (read <= 0)
                    {
                        break;
                    }

                    await localStream.WriteAsync(buffer.AsMemory(0, read), cancellationToken).ConfigureAwait(false);
                    downloaded += read;

                    long now = Environment.TickCount64;
                    if (now - lastReportTicks >= 120 || (totalBytes.HasValue && downloaded >= totalBytes.Value))
                    {
                        lastReportTicks = now;
                        double dlMb = downloaded / (1024.0 * 1024.0);
                        if (totalBytes is > 0)
                        {
                            double totalMb = totalBytes.Value / (1024.0 * 1024.0);
                            double pct = Math.Clamp(downloaded * 90.0 / totalBytes.Value, 1, 90);
                            progress?.Report((pct, string.Create(CultureInfo.InvariantCulture, $"Downloading {release.VersionText}: {dlMb:0.0} / {totalMb:0.0} MB")));
                        }
                        else
                        {
                            progress?.Report((45, string.Create(CultureInfo.InvariantCulture, $"Downloading {release.VersionText}: {dlMb:0.0} MB")));
                        }
                    }
                }

                await localStream.FlushAsync(cancellationToken).ConfigureAwait(false);
            }

            if (string.IsNullOrWhiteSpace(release.Sha256SumsUrl) && string.IsNullOrWhiteSpace(release.Sha256ApiUrl))
            {
                throw new InvalidOperationException("Release does not provide SHA256SUMS.txt for verification.");
            }

            progress?.Report((94, "Verifying SHA-256 manifest..."));
            byte[] manifestBytes = await FetchSmallBytesAsync(
                release.Sha256SumsUrl,
                release.Sha256ApiUrl,
                githubToken,
                MaxManifestBytes,
                cancellationToken).ConfigureAwait(false);

            bool hasKey = _ed25519PublicKey.Length == 32;
            bool hasSigUrl = !string.IsNullOrWhiteSpace(release.Sha256SumsSigUrl) || !string.IsNullOrWhiteSpace(release.Sha256SigApiUrl);
            if (requireSignature && (!hasKey || !hasSigUrl))
            {
                throw new CryptographicException("Ed25519 signature verification was required, but key or signature asset is missing.");
            }

            ImmutableArray<ManifestEntry> entries;
            bool signatureVerified = false;

            if (hasKey && hasSigUrl)
            {
                byte[] sigRaw = await FetchSmallBytesAsync(
                    release.Sha256SumsSigUrl,
                    release.Sha256SigApiUrl,
                    githubToken,
                    MaxSignatureBytes,
                    cancellationToken).ConfigureAwait(false);

                if (!TryDecodeSignatureBytes(sigRaw, out byte[] sigBytes) ||
                    !SignedManifestVerifier.VerifySignedManifest(manifestBytes, sigBytes, _ed25519PublicKey.Span, out entries))
                {
                    throw new CryptographicException("Detached Ed25519 signature verification failed for SHA256SUMS.txt.");
                }

                signatureVerified = true;
            }
            else
            {
                string manifestText = Encoding.UTF8.GetString(manifestBytes);
                entries = SignedManifestVerifier.ParseSha256Sums(manifestText);
            }

            ManifestEntry? targetEntry = FindManifestEntry(entries, fileName);
            if (targetEntry is null)
            {
                throw new InvalidDataException(string.Create(CultureInfo.InvariantCulture, $"SHA256SUMS.txt does not contain an entry for '{fileName}'."));
            }

            progress?.Report((97, "Verifying downloaded file SHA-256 digest..."));
            await using (FileStream verifyStream = new(partPath, FileMode.Open, FileAccess.Read, FileShare.Read, 81920, FileOptions.Asynchronous))
            {
                bool matches = await SignedManifestVerifier.VerifyManifestEntryAsync(verifyStream, targetEntry, cancellationToken).ConfigureAwait(false);
                if (!matches)
                {
                    throw new CryptographicException(string.Create(CultureInfo.InvariantCulture, $"SHA-256 checksum mismatch for '{fileName}'."));
                }
            }

            bool authenticodePresent = TryInspectAuthenticode(partPath, out string? authenticodeSubject);
            File.Move(partPath, finalPath, overwrite: true);

            string sha256Hex = Convert.ToHexString(targetEntry.Sha256Hash.AsSpan()).ToLowerInvariant();
            string summary = signatureVerified
                ? string.Create(CultureInfo.InvariantCulture, $"Verified SHA-256 and Ed25519 signature for {fileName}.")
                : string.Create(CultureInfo.InvariantCulture, $"Verified SHA-256 checksum for {fileName}.");

            progress?.Report((100, summary));
            return new VerifiedUpdateResult(
                Verified: true,
                PreparedFilePath: finalPath,
                IsInstaller: actuallyInstaller,
                Sha256Hex: sha256Hex,
                SignatureVerified: signatureVerified,
                AuthenticodePresent: authenticodePresent,
                AuthenticodeSubject: authenticodeSubject,
                Summary: summary);
        }
        catch
        {
            TryDeleteFile(partPath);
            throw;
        }
    }

    /// <summary>
    /// Inspects optional Windows Authenticode signature metadata on <paramref name="filePath"/> without failing when unsigned.
    /// </summary>
    public static bool TryInspectAuthenticode(string filePath, out string? subject)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(filePath);
        subject = null;

        try
        {
#pragma warning disable SYSLIB0057 // X509CertificateLoader does not extract PE Authenticode signatures from executable files.
            using X509Certificate rawCert = X509Certificate2.CreateFromSignedFile(filePath);
#pragma warning restore SYSLIB0057
            using X509Certificate2 cert2 = X509CertificateLoader.LoadCertificate(rawCert.GetRawCertData());
            subject = cert2.Subject;
            return !string.IsNullOrWhiteSpace(subject);
        }
        catch (CryptographicException)
        {
            return false;
        }
        catch (IOException)
        {
            return false;
        }
        catch (UnauthorizedAccessException)
        {
            return false;
        }
    }

    /// <summary>
    /// Builds a <see cref="ProcessStartInfo"/> that launches the staged Inno Setup installer silently
    /// (<c>/VERYSILENT /SUPPRESSMSGBOXES /NORESTART</c>).
    /// </summary>
    public static ProcessStartInfo CreateSilentInstallerStartInfo(string stagedInstallerPath)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(stagedInstallerPath);

        string fullPath = Path.GetFullPath(stagedInstallerPath);
        if (!File.Exists(fullPath))
        {
            throw new FileNotFoundException("Staged installer binary does not exist.", fullPath);
        }

        return new ProcessStartInfo
        {
            FileName = fullPath,
            Arguments = SilentInnoSetupArguments,
            UseShellExecute = true,
            WorkingDirectory = Path.GetDirectoryName(fullPath) ?? string.Empty
        };
    }

    /// <inheritdoc />
    public void Dispose()
    {
        if (_disposed)
        {
            return;
        }

        _disposed = true;
        _bootstrapCheckClient.Dispose();
        _bootstrapDownloadClient.Dispose();
        _systemProxyCheckClient.Dispose();
        _systemProxyDownloadClient.Dispose();
        _ownedBootstrapCheckHandler?.Dispose();
        _ownedBootstrapDownloadHandler?.Dispose();
        _ownedSystemProxyCheckHandler?.Dispose();
        _ownedSystemProxyDownloadHandler?.Dispose();
    }

    private async Task<byte[]> FetchSmallBytesAsync(
        string? browserUrl,
        string? apiUrl,
        string? githubToken,
        int maxBytes,
        CancellationToken cancellationToken)
    {
        using HttpResponseMessage resp = await SendAssetDownloadAsync(browserUrl, apiUrl, githubToken, cancellationToken).ConfigureAwait(false);
        await using Stream stream = await resp.Content.ReadAsStreamAsync(cancellationToken).ConfigureAwait(false);
        using MemoryStream ms = new();
        byte[] buffer = new byte[8192];
        int total = 0;

        while (true)
        {
            int read = await stream.ReadAsync(buffer, cancellationToken).ConfigureAwait(false);
            if (read <= 0)
            {
                break;
            }

            total += read;
            if (total > maxBytes)
            {
                throw new InvalidDataException("Update metadata asset exceeded maximum allowed size.");
            }

            await ms.WriteAsync(buffer.AsMemory(0, read), cancellationToken).ConfigureAwait(false);
        }

        return ms.ToArray();
    }

    private async Task<HttpResponseMessage> SendAssetDownloadAsync(
        string? browserUrl,
        string? apiUrl,
        string? githubToken,
        CancellationToken cancellationToken)
    {
        string token = (githubToken ?? string.Empty).Trim();
        string? targetUrl = browserUrl;

        if (token.Length > 0 && !string.IsNullOrWhiteSpace(apiUrl))
        {
            foreach (HttpClient checkClient in _checkClients)
            {
                try
                {
                    using HttpRequestMessage apiReq = new(HttpMethod.Get, apiUrl);
                    apiReq.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);
                    apiReq.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/octet-stream"));

                    using HttpResponseMessage apiResp = await checkClient.SendAsync(apiReq, HttpCompletionOption.ResponseHeadersRead, cancellationToken).ConfigureAwait(false);
                    if (apiResp.Headers.Location is { } redirect)
                    {
                        targetUrl = redirect.ToString();
                        break;
                    }

                    if (apiResp.IsSuccessStatusCode)
                    {
                        targetUrl = apiUrl;
                        break;
                    }
                }
                catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
                {
                    throw;
                }
                catch (HttpRequestException)
                {
                }
                catch (IOException)
                {
                }
                catch (SocketException)
                {
                }
            }
        }

        if (string.IsNullOrWhiteSpace(targetUrl))
        {
            throw new InvalidOperationException("Release asset URL is missing.");
        }

        Exception? lastError = null;
        foreach (HttpClient dlClient in _downloadClients)
        {
            try
            {
                using HttpRequestMessage req = new(HttpMethod.Get, targetUrl);
                if (token.Length > 0 && targetUrl.StartsWith("https://api.github.com/", StringComparison.OrdinalIgnoreCase))
                {
                    req.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);
                    req.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/octet-stream"));
                }

                HttpResponseMessage resp = await dlClient.SendAsync(req, HttpCompletionOption.ResponseHeadersRead, cancellationToken).ConfigureAwait(false);
                if (resp.IsSuccessStatusCode)
                {
                    return resp;
                }

                lastError = new HttpRequestException(string.Create(CultureInfo.InvariantCulture, $"HTTP {(int)resp.StatusCode}"));
                resp.Dispose();
            }
            catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
            {
                throw;
            }
            catch (HttpRequestException ex)
            {
                lastError = ex;
            }
            catch (IOException ex)
            {
                lastError = ex;
            }
            catch (SocketException ex)
            {
                lastError = ex;
            }
            catch (OperationCanceledException ex)
            {
                lastError = ex;
            }
        }

        throw lastError ?? new HttpRequestException("Failed to download release asset from GitHub.");
    }

    private static ReleaseInfo? ParseReleaseElement(JsonElement root)
    {
        string tag = root.TryGetProperty("tag_name", out JsonElement tagEl) && tagEl.ValueKind == JsonValueKind.String
            ? (tagEl.GetString() ?? string.Empty).Trim()
            : string.Empty;
        if (!TryParseVersion(tag, out Version parsedVersion))
        {
            return null;
        }

        bool isPrerelease = root.TryGetProperty("prerelease", out JsonElement preEl) && preEl.ValueKind == JsonValueKind.True;
        string notes = root.TryGetProperty("body", out JsonElement bodyEl) && bodyEl.ValueKind == JsonValueKind.String
            ? (bodyEl.GetString() ?? string.Empty)
            : string.Empty;
        string htmlUrl = root.TryGetProperty("html_url", out JsonElement htmlEl) && htmlEl.ValueKind == JsonValueKind.String
            ? (htmlEl.GetString() ?? WebLatestUrl)
            : WebLatestUrl;

        string? setupUrl = null;
        string? portableUrl = null;
        string? shaUrl = null;
        string? shaSigUrl = null;
        string? setupApiUrl = null;
        string? portableApiUrl = null;
        string? shaApiUrl = null;
        string? shaSigApiUrl = null;

        if (root.TryGetProperty("assets", out JsonElement assetsEl) && assetsEl.ValueKind == JsonValueKind.Array)
        {
            foreach (JsonElement asset in assetsEl.EnumerateArray())
            {
                if (asset.ValueKind != JsonValueKind.Object)
                {
                    continue;
                }

                string name = asset.TryGetProperty("name", out JsonElement nameEl) && nameEl.ValueKind == JsonValueKind.String
                    ? (nameEl.GetString() ?? string.Empty)
                    : string.Empty;
                string? url = asset.TryGetProperty("browser_download_url", out JsonElement dlEl) && dlEl.ValueKind == JsonValueKind.String
                    ? dlEl.GetString()
                    : null;
                string? apiUrl = asset.TryGetProperty("url", out JsonElement urlEl) && urlEl.ValueKind == JsonValueKind.String
                    ? urlEl.GetString()
                    : null;

                if (string.IsNullOrWhiteSpace(url) && string.IsNullOrWhiteSpace(apiUrl))
                {
                    continue;
                }

                if (name.Equals(SetupInstallerAssetName, StringComparison.OrdinalIgnoreCase))
                {
                    setupUrl = url;
                    setupApiUrl = apiUrl;
                }
                else if (name.Equals(PortableExecutableAssetName, StringComparison.OrdinalIgnoreCase))
                {
                    portableUrl = url;
                    portableApiUrl = apiUrl;
                }
                else if (name.Equals(Sha256SumsAssetName, StringComparison.OrdinalIgnoreCase))
                {
                    shaUrl = url;
                    shaApiUrl = apiUrl;
                }
                else if (name.Equals(Sha256SumsSigAssetName, StringComparison.OrdinalIgnoreCase)
                    || name.Equals("SHA256SUMS.sig", StringComparison.OrdinalIgnoreCase))
                {
                    shaSigUrl = url;
                    shaSigApiUrl = apiUrl;
                }
            }
        }

        string versionText = tag.StartsWith('v') || tag.StartsWith('V') ? tag : string.Concat("v", tag);
        return new ReleaseInfo(
            TagName: tag,
            VersionText: versionText,
            ParsedVersion: parsedVersion,
            IsPrerelease: isPrerelease,
            ReleaseNotes: notes,
            SetupExeUrl: setupUrl,
            PortableExeUrl: portableUrl,
            Sha256SumsUrl: shaUrl,
            Sha256SumsSigUrl: shaSigUrl,
            HtmlUrl: htmlUrl,
            SetupApiUrl: setupApiUrl,
            PortableApiUrl: portableApiUrl,
            Sha256ApiUrl: shaApiUrl,
            Sha256SigApiUrl: shaSigApiUrl);
    }

    private static bool IsCandidateNewerThan(ReleaseInfo candidate, ReleaseInfo currentBest)
    {
        int cmp = CompareVersions(candidate.ParsedVersion, currentBest.ParsedVersion);
        if (cmp != 0)
        {
            return cmp > 0;
        }

        return !candidate.IsPrerelease && currentBest.IsPrerelease;
    }

    private static ManifestEntry? FindManifestEntry(ImmutableArray<ManifestEntry> entries, string targetFileName)
    {
        foreach (ManifestEntry entry in entries)
        {
            if (entry.FileName.Equals(targetFileName, StringComparison.OrdinalIgnoreCase) ||
                Path.GetFileName(entry.FileName).Equals(targetFileName, StringComparison.OrdinalIgnoreCase))
            {
                return entry;
            }
        }

        return null;
    }

    private static bool TryDecodeSignatureBytes(byte[] rawBytes, out byte[] signature)
    {
        if (rawBytes.Length == 64)
        {
            signature = rawBytes;
            return true;
        }

        string text = Encoding.UTF8.GetString(rawBytes).Trim();
        if (text.Length == 128)
        {
            try
            {
                byte[] hexBytes = Convert.FromHexString(text);
                if (hexBytes.Length == 64)
                {
                    signature = hexBytes;
                    return true;
                }
            }
            catch (FormatException)
            {
            }
        }

        try
        {
            string normalized = text.Replace('-', '+').Replace('_', '/');
            int mod = normalized.Length % 4;
            if (mod == 2)
            {
                normalized = string.Concat(normalized, "==");
            }
            else if (mod == 3)
            {
                normalized = string.Concat(normalized, "=");
            }

            byte[] b64 = Convert.FromBase64String(normalized);
            if (b64.Length == 64)
            {
                signature = b64;
                return true;
            }
        }
        catch (FormatException)
        {
        }

        signature = [];
        return false;
    }

    private static string SanitizePathSegment(string segment)
    {
        StringBuilder sb = new(segment.Length);
        foreach (char c in segment)
        {
            if (char.IsAsciiLetterOrDigit(c) || c is '.' or '-' or '_')
            {
                sb.Append(c);
            }
            else
            {
                sb.Append('_');
            }
        }

        string sanitized = sb.ToString().Trim('.');
        return sanitized.Length == 0 ? "release" : sanitized;
    }

    private static void TryDeleteFile(string path)
    {
        try
        {
            if (File.Exists(path))
            {
                File.Delete(path);
            }
        }
        catch (IOException)
        {
        }
        catch (UnauthorizedAccessException)
        {
        }
    }

    private static HttpClient CreateConfiguredClient(
        HttpMessageHandler handler,
        TimeSpan timeout,
        bool acceptGitHubJson)
    {
        HttpClient client = new(handler, disposeHandler: false)
        {
            Timeout = timeout,
            DefaultRequestVersion = HttpVersion.Version11,
            DefaultVersionPolicy = HttpVersionPolicy.RequestVersionOrLower
        };
        client.DefaultRequestHeaders.UserAgent.Add(new ProductInfoHeaderValue("DnsPulse-Updater", "2.0"));
        if (acceptGitHubJson)
        {
            client.DefaultRequestHeaders.Accept.Add(new MediaTypeWithQualityHeaderValue("application/vnd.github+json"));
        }

        return client;
    }

    private static SocketsHttpHandler CreateSystemProxySocketsHandler(bool allowAutoRedirect)
    {
        return new SocketsHttpHandler
        {
            AllowAutoRedirect = allowAutoRedirect,
            MaxAutomaticRedirections = 4,
            AutomaticDecompression = DecompressionMethods.All,
            ConnectTimeout = TimeSpan.FromSeconds(8),
            PooledConnectionLifetime = TimeSpan.FromMinutes(2)
        };
    }

    private static SocketsHttpHandler CreateBootstrapSocketsHandler(IBootstrapResolver bootstrapResolver, bool allowAutoRedirect)
    {
        return new SocketsHttpHandler
        {
            AllowAutoRedirect = allowAutoRedirect,
            MaxAutomaticRedirections = 4,
            AutomaticDecompression = DecompressionMethods.All,
            PooledConnectionLifetime = TimeSpan.FromMinutes(2),
            ConnectCallback = async (context, ct) =>
            {
                IReadOnlyList<IPAddress> candidateIps = IPAddress.TryParse(context.DnsEndPoint.Host, out IPAddress? literalIp)
                    ? [literalIp]
                    : await bootstrapResolver.ResolveHostAsync(context.DnsEndPoint.Host, ct).ConfigureAwait(false);

                SocketException? lastSocketEx = null;
                foreach (IPAddress ip in candidateIps)
                {
                    if (!IpSafetyInspector.IsPublicRoutable(ip))
                    {
                        continue;
                    }

                    Socket socket = new(ip.AddressFamily, SocketType.Stream, ProtocolType.Tcp)
                    {
                        NoDelay = true
                    };

                    try
                    {
                        await socket.ConnectAsync(new IPEndPoint(ip, context.DnsEndPoint.Port), ct).ConfigureAwait(false);
                        return new NetworkStream(socket, ownsSocket: true);
                    }
                    catch (SocketException ex)
                    {
                        lastSocketEx = ex;
                        socket.Dispose();
                    }
                    catch
                    {
                        socket.Dispose();
                        throw;
                    }
                }

                throw lastSocketEx ?? new SocketException((int)SocketError.HostNotFound);
            }
        };
    }
}
