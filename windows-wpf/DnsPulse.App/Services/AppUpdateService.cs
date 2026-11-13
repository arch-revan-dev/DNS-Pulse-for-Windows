using System.Diagnostics;
using System.IO;
using System.Net;
using System.Net.Http;
using System.Reflection;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using DnsPulse.App.NetworkEngine;

namespace DnsPulse.App.Services;

public sealed record AppReleaseInfo(
    string TagName,
    string VersionText,
    Version ParsedVersion,
    string ReleaseNotes,
    string? SetupExeUrl,
    string? PortableExeUrl,
    string? Sha256SumsUrl,
    string HtmlUrl,
    string? SetupApiUrl = null,
    string? PortableApiUrl = null,
    string? Sha256ApiUrl = null);

public sealed record UpdateCheckResult(
    bool UpdateAvailable,
    Version CurrentVersion,
    AppReleaseInfo? LatestRelease,
    string? ErrorMessage = null);

public sealed class AppUpdateService
{
    public const string RepoOwner = "arch-revan-dev";
    public const string RepoName = "DNS-Pulse-for-Windows";
    private const string ApiLatestUrl = $"https://api.github.com/repos/{RepoOwner}/{RepoName}/releases/latest";
    private const string WebLatestUrl = $"https://github.com/{RepoOwner}/{RepoName}/releases/latest";

    private readonly HttpClient _checkClient;
    private readonly HttpClient _downloadClient;
    private readonly HttpClient _systemProxyCheckClient;
    private readonly HttpClient _systemProxyDownloadClient;

    public AppUpdateService()
    {
        _checkClient = BootstrapDnsResolver.CreateBootstrapHttpClient(TimeSpan.FromSeconds(12), allowAutoRedirect: false);
        _checkClient.DefaultRequestVersion = HttpVersion.Version11;
        _checkClient.DefaultVersionPolicy = HttpVersionPolicy.RequestVersionOrLower;
        _checkClient.DefaultRequestHeaders.TryAddWithoutValidation("Accept", "application/vnd.github+json");
        _checkClient.DefaultRequestHeaders.TryAddWithoutValidation("User-Agent", "DNS-Pulse-Updater/1.5");

        _downloadClient = BootstrapDnsResolver.CreateBootstrapHttpClient(TimeSpan.FromMinutes(6), allowAutoRedirect: true);
        _downloadClient.DefaultRequestVersion = HttpVersion.Version11;
        _downloadClient.DefaultVersionPolicy = HttpVersionPolicy.RequestVersionOrLower;
        _downloadClient.DefaultRequestHeaders.TryAddWithoutValidation("User-Agent", "DNS-Pulse-Updater/1.5");

        // Fallback clients honoring Windows system proxy / VPN adapter routes if direct UDP bootstrap is blocked
        _systemProxyCheckClient = new HttpClient(new SocketsHttpHandler
        {
            AllowAutoRedirect = false,
            AutomaticDecompression = DecompressionMethods.GZip | DecompressionMethods.Deflate | DecompressionMethods.Brotli,
            ConnectTimeout = TimeSpan.FromSeconds(6)
        })
        {
            Timeout = TimeSpan.FromSeconds(12)
        };
        _systemProxyCheckClient.DefaultRequestHeaders.TryAddWithoutValidation("Accept", "application/vnd.github+json");
        _systemProxyCheckClient.DefaultRequestHeaders.TryAddWithoutValidation("User-Agent", "DNS-Pulse-Updater/1.5");

        _systemProxyDownloadClient = new HttpClient(new SocketsHttpHandler
        {
            AllowAutoRedirect = true,
            AutomaticDecompression = DecompressionMethods.GZip | DecompressionMethods.Deflate | DecompressionMethods.Brotli,
            ConnectTimeout = TimeSpan.FromSeconds(8)
        })
        {
            Timeout = TimeSpan.FromMinutes(6)
        };
        _systemProxyDownloadClient.DefaultRequestHeaders.TryAddWithoutValidation("User-Agent", "DNS-Pulse-Updater/1.5");
    }

    public static Version GetCurrentVersion()
    {
        var asm = Assembly.GetEntryAssembly() ?? typeof(AppUpdateService).Assembly;
        var infoVer = asm.GetCustomAttribute<AssemblyInformationalVersionAttribute>()?.InformationalVersion;
        if (!string.IsNullOrWhiteSpace(infoVer) && TryParseVersion(infoVer, out var parsedInfo))
            return parsedInfo;

        var asmVer = asm.GetName().Version;
        if (asmVer is not null)
            return new Version(asmVer.Major, Math.Max(0, asmVer.Minor), Math.Max(0, asmVer.Build));

        return new Version(1, 3, 0);
    }

    public static bool IsInstalledEdition(string? exePath = null)
    {
        var exe = exePath ?? Environment.ProcessPath;
        if (string.IsNullOrWhiteSpace(exe))
            return false;

        var dir = Path.GetDirectoryName(exe);
        if (string.IsNullOrWhiteSpace(dir))
            return false;

        return File.Exists(Path.Combine(dir, "unins000.exe"));
    }

    public static bool TryParseVersion(string? raw, out Version version)
    {
        version = new Version(0, 0, 0);
        if (string.IsNullOrWhiteSpace(raw))
            return false;

        var s = raw.Trim();
        if (s.StartsWith('v') || s.StartsWith('V'))
            s = s[1..];

        var plusIdx = s.IndexOf('+');
        if (plusIdx >= 0) s = s[..plusIdx];
        var dashIdx = s.IndexOf('-');
        if (dashIdx >= 0) s = s[..dashIdx];

        if (!Version.TryParse(s, out var parsed) || parsed is null)
            return false;

        version = parsed.Build < 0
            ? new Version(parsed.Major, Math.Max(0, parsed.Minor), 0)
            : parsed.Revision >= 0
                ? new Version(parsed.Major, parsed.Minor, parsed.Build, parsed.Revision)
                : new Version(parsed.Major, parsed.Minor, parsed.Build);
        return true;
    }

    public static AppReleaseInfo? ParseReleaseJson(string json)
    {
        if (string.IsNullOrWhiteSpace(json))
            return null;

        using var doc = JsonDocument.Parse(json);
        var root = doc.RootElement;
        if (root.ValueKind != JsonValueKind.Object)
            return null;

        var tag = root.TryGetProperty("tag_name", out var tagEl) ? (tagEl.GetString() ?? string.Empty).Trim() : string.Empty;
        if (!TryParseVersion(tag, out var parsedVersion))
            return null;

        var notes = root.TryGetProperty("body", out var bodyEl) ? (bodyEl.GetString() ?? string.Empty) : string.Empty;
        var htmlUrl = root.TryGetProperty("html_url", out var htmlEl) ? (htmlEl.GetString() ?? WebLatestUrl) : WebLatestUrl;

        string? setupUrl = null;
        string? portableUrl = null;
        string? shaUrl = null;
        string? setupApiUrl = null;
        string? portableApiUrl = null;
        string? shaApiUrl = null;

        if (root.TryGetProperty("assets", out var assetsEl) && assetsEl.ValueKind == JsonValueKind.Array)
        {
            foreach (var asset in assetsEl.EnumerateArray())
            {
                var name = asset.TryGetProperty("name", out var n) ? (n.GetString() ?? string.Empty) : string.Empty;
                var url = asset.TryGetProperty("browser_download_url", out var u) ? u.GetString() : null;
                var apiUrl = asset.TryGetProperty("url", out var au) ? au.GetString() : null;
                if (string.IsNullOrWhiteSpace(url) && string.IsNullOrWhiteSpace(apiUrl)) continue;

                if (name.Equals("DNS-Pulse-win-x64-setup.exe", StringComparison.OrdinalIgnoreCase))
                {
                    setupUrl = url;
                    setupApiUrl = apiUrl;
                }
                else if (name.Equals("DnsPulse.exe", StringComparison.OrdinalIgnoreCase))
                {
                    portableUrl = url;
                    portableApiUrl = apiUrl;
                }
                else if (name.Equals("SHA256SUMS.txt", StringComparison.OrdinalIgnoreCase))
                {
                    shaUrl = url;
                    shaApiUrl = apiUrl;
                }
            }
        }

        return new AppReleaseInfo(
            TagName: tag,
            VersionText: tag.StartsWith('v') || tag.StartsWith('V') ? tag : $"v{tag}",
            ParsedVersion: parsedVersion,
            ReleaseNotes: notes,
            SetupExeUrl: setupUrl,
            PortableExeUrl: portableUrl,
            Sha256SumsUrl: shaUrl,
            HtmlUrl: htmlUrl,
            SetupApiUrl: setupApiUrl,
            PortableApiUrl: portableApiUrl,
            Sha256ApiUrl: shaApiUrl);
    }

    public static Dictionary<string, string> ParseSha256Sums(string rawText)
    {
        var map = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        if (string.IsNullOrWhiteSpace(rawText))
            return map;

        foreach (var line in rawText.Split(new[] { '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries))
        {
            var parts = line.Trim().Split((char[]?)null, StringSplitOptions.RemoveEmptyEntries);
            if (parts.Length >= 2 && parts[0].Length == 64)
            {
                map[parts[^1].TrimStart('*')] = parts[0].ToLowerInvariant();
            }
        }
        return map;
    }

    public async Task<UpdateCheckResult> CheckForUpdateAsync(CancellationToken ct = default, string? githubToken = null)
    {
        var current = GetCurrentVersion();
        AppReleaseInfo? latest = null;
        int? lastApiStatus = null;
        string? transportError = null;
        var token = (githubToken ?? string.Empty).Trim();

        // 1. Try GitHub Releases API (first via Bootstrap DNS, then via Windows System Proxy fallback)
        foreach (var client in new[] { _checkClient, _systemProxyCheckClient })
        {
            if (latest is not null || ct.IsCancellationRequested) break;
            try
            {
                using var req = new HttpRequestMessage(HttpMethod.Get, ApiLatestUrl);
                if (!string.IsNullOrEmpty(token))
                    req.Headers.TryAddWithoutValidation("Authorization", $"Bearer {token}");

                using var resp = await client.SendAsync(req, ct).ConfigureAwait(false);
                lastApiStatus = (int)resp.StatusCode;
                if (resp.IsSuccessStatusCode)
                {
                    var json = await resp.Content.ReadAsStringAsync(ct).ConfigureAwait(false);
                    latest = ParseReleaseJson(json);
                    break;
                }
            }
            catch (OperationCanceledException) when (ct.IsCancellationRequested)
            {
                throw;
            }
            catch (Exception ex)
            {
                transportError = ex.Message;
            }
        }

        // 2. Fallback: HTTP GET redirect on github.com/.../releases/latest (no API quota limits)
        int? webStatus = null;
        if (latest is null)
        {
            foreach (var client in new[] { _checkClient, _systemProxyCheckClient })
            {
                if (latest is not null || ct.IsCancellationRequested) break;
                try
                {
                    using var req = new HttpRequestMessage(HttpMethod.Get, WebLatestUrl);
                    using var resp = await client.SendAsync(req, HttpCompletionOption.ResponseHeadersRead, ct).ConfigureAwait(false);
                    webStatus = (int)resp.StatusCode;
                    var loc = resp.Headers.Location?.ToString() ?? string.Empty;
                    var marker = "/releases/tag/";
                    var idx = loc.IndexOf(marker, StringComparison.OrdinalIgnoreCase);
                    if (idx >= 0)
                    {
                        var tag = loc[(idx + marker.Length)..].Trim().TrimEnd('/');
                        if (TryParseVersion(tag, out var ver))
                        {
                            var dlBase = $"https://github.com/{RepoOwner}/{RepoName}/releases/download/{tag}";
                            latest = new AppReleaseInfo(
                                TagName: tag,
                                VersionText: tag.StartsWith('v') || tag.StartsWith('V') ? tag : $"v{tag}",
                                ParsedVersion: ver,
                                ReleaseNotes: string.Empty,
                                SetupExeUrl: $"{dlBase}/DNS-Pulse-win-x64-setup.exe",
                                PortableExeUrl: $"{dlBase}/DnsPulse.exe",
                                Sha256SumsUrl: $"{dlBase}/SHA256SUMS.txt",
                                HtmlUrl: $"https://github.com/{RepoOwner}/{RepoName}/releases/tag/{tag}");
                        }
                    }
                }
                catch (OperationCanceledException) when (ct.IsCancellationRequested)
                {
                    throw;
                }
                catch (Exception ex)
                {
                    transportError ??= ex.Message;
                }
            }
        }

        string? errorMsg = null;
        if (latest is null)
        {
            int? code = lastApiStatus ?? webStatus;
            errorMsg = code switch
            {
                404 => "Репозиторий приватный или релиз скрыт (HTTP 404). Сделайте репозиторий Public на GitHub или укажите GitHub Token в Настройках.",
                401 => "Неверный или просроченный GitHub Token (HTTP 401).",
                403 or 429 => "Лимит запросов GitHub API исчерпан (HTTP 403/429). Попробуйте позже или укажите токен.",
                not null => $"GitHub вернул HTTP {code} при проверке обновлений.",
                null => string.IsNullOrWhiteSpace(transportError)
                    ? "Не удалось подключиться к GitHub (проверьте интернет или DNS)."
                    : $"Ошибка сети при подключении к GitHub: {transportError}"
            };
        }

        bool available = latest is not null && CompareVersions(latest.ParsedVersion, current) > 0;
        return new UpdateCheckResult(available, current, latest, errorMsg);
    }

    public static int CompareVersions(Version a, Version b)
    {
        int cmp = a.Major.CompareTo(b.Major);
        if (cmp != 0) return cmp;
        cmp = Math.Max(0, a.Minor).CompareTo(Math.Max(0, b.Minor));
        if (cmp != 0) return cmp;
        cmp = Math.Max(0, a.Build).CompareTo(Math.Max(0, b.Build));
        if (cmp != 0) return cmp;
        return Math.Max(0, a.Revision).CompareTo(Math.Max(0, b.Revision));
    }

    private async Task<HttpResponseMessage> SendAssetDownloadAsync(
        string? browserUrl,
        string? apiUrl,
        string? githubToken,
        CancellationToken ct)
    {
        var token = (githubToken ?? string.Empty).Trim();
        string? targetUrl = browserUrl;

        // For private repos with a token, resolve the short-lived CDN redirect URL via GitHub Release Asset API
        if (!string.IsNullOrEmpty(token) && !string.IsNullOrWhiteSpace(apiUrl))
        {
            foreach (var checkClient in new[] { _checkClient, _systemProxyCheckClient })
            {
                try
                {
                    using var apiReq = new HttpRequestMessage(HttpMethod.Get, apiUrl);
                    apiReq.Headers.TryAddWithoutValidation("Authorization", $"Bearer {token}");
                    apiReq.Headers.TryAddWithoutValidation("Accept", "application/octet-stream");
                    using var apiResp = await checkClient.SendAsync(apiReq, HttpCompletionOption.ResponseHeadersRead, ct).ConfigureAwait(false);
                    if (apiResp.Headers.Location is { } redir)
                    {
                        targetUrl = redir.ToString();
                        break;
                    }
                    if (apiResp.IsSuccessStatusCode)
                    {
                        targetUrl = apiUrl;
                        break;
                    }
                }
                catch (OperationCanceledException) when (ct.IsCancellationRequested)
                {
                    throw;
                }
                catch
                {
                    // Try fallback client
                }
            }
        }

        if (string.IsNullOrWhiteSpace(targetUrl))
            throw new InvalidOperationException("URL файла релиза отсутствует.");

        Exception? lastErr = null;
        foreach (var dlClient in new[] { _downloadClient, _systemProxyDownloadClient })
        {
            try
            {
                using var req = new HttpRequestMessage(HttpMethod.Get, targetUrl);
                if (!string.IsNullOrEmpty(token) && targetUrl.StartsWith("https://api.github.com/", StringComparison.OrdinalIgnoreCase))
                {
                    req.Headers.TryAddWithoutValidation("Authorization", $"Bearer {token}");
                    req.Headers.TryAddWithoutValidation("Accept", "application/octet-stream");
                }
                var resp = await dlClient.SendAsync(req, HttpCompletionOption.ResponseHeadersRead, ct).ConfigureAwait(false);
                if (resp.IsSuccessStatusCode)
                    return resp;
                lastErr = new HttpRequestException($"HTTP {(int)resp.StatusCode}");
                resp.Dispose();
            }
            catch (OperationCanceledException) when (ct.IsCancellationRequested)
            {
                throw;
            }
            catch (Exception ex)
            {
                lastErr = ex;
            }
        }

        throw lastErr ?? new HttpRequestException("Не удалось скачать файл обновления с GitHub.");
    }

    public async Task<(string PreparedFilePath, bool IsInstaller)> DownloadAndVerifyUpdateAsync(
        AppReleaseInfo release,
        IProgress<(double Percent, string Status)>? progress,
        CancellationToken ct,
        string? githubToken = null)
    {
        bool useInstaller = IsInstalledEdition() && (!string.IsNullOrWhiteSpace(release.SetupExeUrl) || !string.IsNullOrWhiteSpace(release.SetupApiUrl));
        string? assetUrl = useInstaller ? release.SetupExeUrl : (release.PortableExeUrl ?? release.SetupExeUrl);
        string? assetApiUrl = useInstaller ? release.SetupApiUrl : (release.PortableApiUrl ?? release.SetupApiUrl);
        if (string.IsNullOrWhiteSpace(assetUrl) && string.IsNullOrWhiteSpace(assetApiUrl))
            throw new InvalidOperationException("В релизе не найден исполняемый файл для Windows x64.");

        bool actuallyInstaller = (assetUrl ?? string.Empty).EndsWith("setup.exe", StringComparison.OrdinalIgnoreCase) || useInstaller;
        string fileName = actuallyInstaller ? "DNS-Pulse-win-x64-setup.exe" : "DnsPulse.exe";
        string stageDir = Path.Combine(Path.GetTempPath(), "DNS-Pulse-update", release.TagName);
        Directory.CreateDirectory(stageDir);
        string targetPath = Path.Combine(stageDir, fileName);

        progress?.Report((2, $"Подключение к GitHub для загрузки {release.VersionText}..."));

        using (var resp = await SendAssetDownloadAsync(assetUrl, assetApiUrl, githubToken, ct).ConfigureAwait(false))
        {
            long? totalBytes = resp.Content.Headers.ContentLength;
            await using var remoteStream = await resp.Content.ReadAsStreamAsync(ct).ConfigureAwait(false);
            await using var localStream = new FileStream(targetPath, FileMode.Create, FileAccess.Write, FileShare.None, 81920, useAsync: true);

            var buffer = new byte[81920];
            long downloaded = 0;
            int read;
            long lastReportTicks = 0;

            while ((read = await remoteStream.ReadAsync(buffer, ct).ConfigureAwait(false)) > 0)
            {
                await localStream.WriteAsync(buffer.AsMemory(0, read), ct).ConfigureAwait(false);
                downloaded += read;

                var now = Environment.TickCount64;
                if (now - lastReportTicks >= 120 || (totalBytes.HasValue && downloaded >= totalBytes.Value))
                {
                    lastReportTicks = now;
                    double dlMb = downloaded / (1024.0 * 1024.0);
                    if (totalBytes is > 0)
                    {
                        double totalMb = totalBytes.Value / (1024.0 * 1024.0);
                        double pct = Math.Clamp(downloaded * 95.0 / totalBytes.Value, 1, 95);
                        progress?.Report((pct, $"Загрузка {release.VersionText}: {dlMb:0.0} / {totalMb:0.0} МБ ({pct:0}%)"));
                    }
                    else
                    {
                        progress?.Report((50, $"Загрузка {release.VersionText}: {dlMb:0.0} МБ"));
                    }
                }
            }
        }

        // Verify SHA256 against SHA256SUMS.txt if present
        if (!string.IsNullOrWhiteSpace(release.Sha256SumsUrl) || !string.IsNullOrWhiteSpace(release.Sha256ApiUrl))
        {
            progress?.Report((97, "Проверка целостности SHA-256..."));
            try
            {
                using var sumResp = await SendAssetDownloadAsync(release.Sha256SumsUrl, release.Sha256ApiUrl, githubToken, ct).ConfigureAwait(false);
                var sumsText = await sumResp.Content.ReadAsStringAsync(ct).ConfigureAwait(false);
                var sums = ParseSha256Sums(sumsText);
                if (sums.TryGetValue(fileName, out var expectedHash))
                {
                    await using var fs = File.OpenRead(targetPath);
                    var hashBytes = await SHA256.HashDataAsync(fs, ct).ConfigureAwait(false);
                    var actualHash = Convert.ToHexString(hashBytes).ToLowerInvariant();
                    if (!actualHash.Equals(expectedHash, StringComparison.OrdinalIgnoreCase))
                    {
                        try { File.Delete(targetPath); } catch { /* ignore */ }
                        throw new InvalidOperationException("Ошибка проверки подлинности (SHA-256 файла не совпадает с релизом GitHub).");
                    }
                }
            }
            catch (InvalidOperationException)
            {
                throw;
            }
            catch
            {
                // Ignore transient checksum fetch error if file itself downloaded cleanly
            }
        }

        progress?.Report((100, $"Обновление {release.VersionText} готово к установке — перезапуск..."));
        return (targetPath, actuallyInstaller);
    }

    public static void LaunchPreparedUpdateAndExit(string preparedFilePath, bool isInstaller)
    {
        var currentExe = Environment.ProcessPath
            ?? throw new InvalidOperationException("Не удалось определить путь к текущему процессу.");
        int currentPid = Environment.ProcessId;

        static string EscapePs(string s) => s.Replace("'", "''");
        string prep = EscapePs(preparedFilePath);
        string exe = EscapePs(currentExe);
        string stageDir = EscapePs(Path.GetDirectoryName(preparedFilePath) ?? Path.GetTempPath());

        string script = isInstaller
            ? $@"
$ErrorActionPreference = 'SilentlyContinue'
try {{ Wait-Process -Id {currentPid} -Timeout 20 }} catch {{}}
Start-Sleep -Milliseconds 350
$p = Start-Process -FilePath '{prep}' -ArgumentList '/VERYSILENT','/SUPPRESSMSGBOXES','/NORESTART' -Wait -PassThru
Start-Sleep -Milliseconds 300
if (Test-Path '{exe}') {{ Start-Process -FilePath '{exe}' }}
Remove-Item -Recurse -Force '{stageDir}'
"
            : $@"
$ErrorActionPreference = 'SilentlyContinue'
try {{ Wait-Process -Id {currentPid} -Timeout 20 }} catch {{}}
for ($i = 0; $i -lt 20; $i++) {{
    try {{
        Copy-Item -LiteralPath '{prep}' -Destination '{exe}' -Force -ErrorAction Stop
        break
    }} catch {{
        Start-Sleep -Milliseconds 300
    }}
}}
if (Test-Path '{exe}') {{ Start-Process -FilePath '{exe}' }}
Remove-Item -Recurse -Force '{stageDir}'
";

        var encoded = Convert.ToBase64String(Encoding.Unicode.GetBytes(script));
        Process.Start(new ProcessStartInfo
        {
            FileName = "powershell.exe",
            Arguments = $"-NoProfile -NonInteractive -WindowStyle Hidden -ExecutionPolicy Bypass -EncodedCommand {encoded}",
            UseShellExecute = false,
            CreateNoWindow = true
        });

        System.Windows.Application.Current?.Shutdown();
    }
}
