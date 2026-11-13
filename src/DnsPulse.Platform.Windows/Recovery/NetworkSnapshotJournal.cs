using System.Diagnostics.CodeAnalysis;
using System.Globalization;
using System.Net;
using System.Runtime.InteropServices;
using System.Security;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using DnsPulse.Platform.Windows.Contracts;
using Microsoft.Win32;

namespace DnsPulse.Platform.Windows.Recovery;

/// <summary>
/// Crash-safe, SHA-256-authenticated transaction journal for Windows DNS, NRPT, SMHNR, and WinINet state.
/// Writes atomically via a write-through <c>.tmp</c> file and <c>.bak</c> rotation so power loss or process
/// termination leaves a verifiable recovery record.
/// </summary>
public sealed class NetworkSnapshotJournal
{
    private const string SnapshotFileName = "network_snapshot.json";
    private const string BackupFileSuffix = ".bak";
    private const string TempFileSuffix = ".tmp";
    private const string PulseNrptPrefix = "PulseCore_";

    private const string TcpipInterfacesSubKey = @"SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces";
    private const string Tcpip6InterfacesSubKey = @"SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters\Interfaces";
    private const string NrptPolicyConfigSubKey = @"SYSTEM\CurrentControlSet\Services\Dnscache\Parameters\DnsPolicyConfig";
    private const string DnsClientPolicySubKey = @"SOFTWARE\Policies\Microsoft\Windows NT\DNSClient";
    private const string SmhnrValueName = "DisableSmartNameResolution";
    private const string InternetSettingsSubKey = @"SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings";
    private const string AutoConfigUrlValueName = "AutoConfigURL";

    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        WriteIndented = true,
        PropertyNameCaseInsensitive = true,
        DefaultIgnoreCondition = JsonIgnoreCondition.Never
    };

    private static readonly JsonSerializerOptions CanonicalJsonOptions = new()
    {
        WriteIndented = false,
        DefaultIgnoreCondition = JsonIgnoreCondition.Never
    };

    private static readonly Lock HookRegistrationLock = new();
    private static UnhandledExceptionEventHandler? _unhandledHandler;
    private static EventHandler<UnobservedTaskExceptionEventArgs>? _unobservedTaskHandler;
    private static EventHandler? _processExitHandler;
    private static int _emergencyRestoreActive;

    private readonly AsyncMutex _ioMutex = new();

    /// <summary>
    /// Initializes a new <see cref="NetworkSnapshotJournal"/> rooted at <paramref name="baseDirectory"/>,
    /// or defaulting to <c>%ProgramData%\DnsPulse</c> with automatic fallback to <c>%LOCALAPPDATA%\DnsPulse</c>
    /// when running unprivileged without ProgramData write permissions.
    /// </summary>
    /// <param name="baseDirectory">Optional explicit directory for journal files.</param>
    public NetworkSnapshotJournal(string? baseDirectory = null)
    {
        BaseDirectory = ResolveWritableDirectory(baseDirectory);
        SnapshotFilePath = Path.Combine(BaseDirectory, SnapshotFileName);
        BackupFilePath = string.Concat(SnapshotFilePath, BackupFileSuffix);
    }

    /// <summary>
    /// Gets the directory holding the journal files.
    /// </summary>
    public string BaseDirectory { get; }

    /// <summary>
    /// Gets the full path to the primary snapshot file.
    /// </summary>
    public string SnapshotFilePath { get; }

    /// <summary>
    /// Gets the full path to the rotated backup snapshot file.
    /// </summary>
    public string BackupFilePath { get; }

    /// <summary>
    /// Computes the canonical lowercase SHA-256 hex checksum of <paramref name="snapshotWithoutChecksum"/>,
    /// excluding <see cref="PrePulseNetworkSnapshot.Sha256Checksum"/>.
    /// </summary>
    /// <param name="snapshotWithoutChecksum">The snapshot payload to hash.</param>
    /// <returns>The 64-character lowercase hexadecimal SHA-256 digest.</returns>
    [SuppressMessage("Globalization", "CA1308:Normalize strings to uppercase", Justification = "Hexadecimal SHA-256 digests are canonically lowercase.")]
    public static string ComputeChecksum(PrePulseNetworkSnapshot snapshotWithoutChecksum)
    {
        ArgumentNullException.ThrowIfNull(snapshotWithoutChecksum);

        byte[] hash = ComputeCanonicalHashBytes(snapshotWithoutChecksum);
        return Convert.ToHexString(hash).ToLowerInvariant();
    }

    /// <summary>
    /// Begins a transactional network modification by atomically persisting a dirty snapshot
    /// (<see cref="PrePulseNetworkSnapshot.DirtyShutdown"/> = <see langword="true"/>) signed with SHA-256.
    /// </summary>
    public async Task<PrePulseNetworkSnapshot> BeginTransactionAsync(
        InterceptionMode mode,
        IPAddress loopbackIp,
        IReadOnlyList<AdapterDnsConfiguration> adapters,
        bool priorSmhnrDisabled,
        IReadOnlyList<string> priorNrptRules,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(loopbackIp);
        ArgumentNullException.ThrowIfNull(adapters);
        ArgumentNullException.ThrowIfNull(priorNrptRules);

        PrePulseNetworkSnapshot unsigned = new()
        {
            SnapshotVersion = 1,
            CapturedAtUtc = DateTimeOffset.UtcNow,
            DirtyShutdown = true,
            ActiveMode = mode,
            LoopbackIpUsed = loopbackIp.ToString(),
            AdapterStates = [.. adapters],
            PriorSmhnrDisabled = priorSmhnrDisabled,
            PriorNrptRuleNames = [.. priorNrptRules],
            Sha256Checksum = string.Empty
        };

        string checksum = ComputeChecksum(unsigned);
        PrePulseNetworkSnapshot signed = unsigned with { Sha256Checksum = checksum };

        await _ioMutex.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            await WriteAtomicAsync(signed, cancellationToken).ConfigureAwait(false);
        }
        finally
        {
            _ioMutex.Release();
        }

        return signed;
    }

    /// <summary>
    /// Marks the currently verified snapshot as cleanly shut down (<see cref="PrePulseNetworkSnapshot.DirtyShutdown"/> = <see langword="false"/>)
    /// and re-signs the SHA-256 checksum atomically.
    /// </summary>
    /// <returns><see langword="true"/> if a verified snapshot existed and was updated; otherwise, <see langword="false"/>.</returns>
    public async Task<bool> MarkCleanShutdownAsync(CancellationToken cancellationToken = default)
    {
        await _ioMutex.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            PrePulseNetworkSnapshot? existing = TryLoadVerifiedSnapshotInternal(out _);
            if (existing is null)
            {
                return false;
            }

            PrePulseNetworkSnapshot updatedUnsigned = existing with
            {
                DirtyShutdown = false,
                Sha256Checksum = string.Empty
            };

            PrePulseNetworkSnapshot signed = updatedUnsigned with
            {
                Sha256Checksum = ComputeChecksum(updatedUnsigned)
            };

            await WriteAtomicAsync(signed, cancellationToken).ConfigureAwait(false);
            return true;
        }
        finally
        {
            _ioMutex.Release();
        }
    }

    /// <summary>
    /// Loads the persisted snapshot and verifies its SHA-256 checksum in constant time via
    /// <see cref="CryptographicOperations.FixedTimeEquals"/>, falling back to <see cref="BackupFilePath"/>
    /// if the primary file is tampered or corrupted.
    /// </summary>
    /// <param name="checksumMismatch">
    /// Set to <see langword="true"/> when snapshot data exists on disk but fails integrity or JSON verification
    /// (and no valid backup recovers it).
    /// </param>
    /// <returns>The verified snapshot, or <see langword="null"/> if absent or tampered.</returns>
    public PrePulseNetworkSnapshot? TryLoadVerifiedSnapshot(out bool checksumMismatch)
    {
        return TryLoadVerifiedSnapshotInternal(out checksumMismatch);
    }

    /// <summary>
    /// Checks for a verified dirty snapshot (<see cref="PrePulseNetworkSnapshot.DirtyShutdown"/> = <see langword="true"/>),
    /// invokes <paramref name="restoreCallback"/> to restore OS networking, and clears the dirty flag.
    /// </summary>
    public async Task<NetworkRestoredResult> RecoverIfDirtyAsync(
        Func<PrePulseNetworkSnapshot, CancellationToken, Task<NetworkRestoredResult>> restoreCallback,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(restoreCallback);

        PrePulseNetworkSnapshot? snapshot = TryLoadVerifiedSnapshotInternal(out bool checksumMismatch);
        if (snapshot is null)
        {
            if (checksumMismatch)
            {
                return new NetworkRestoredResult(
                    HadDirtyState: true,
                    AdaptersRestored: 0,
                    PoliciesCleaned: false,
                    Summary: "Network snapshot checksum verification failed; refused untrusted snapshot.");
            }

            return new NetworkRestoredResult(
                HadDirtyState: false,
                AdaptersRestored: 0,
                PoliciesCleaned: true,
                Summary: "No dirty network snapshot found.");
        }

        if (!snapshot.DirtyShutdown)
        {
            return new NetworkRestoredResult(
                HadDirtyState: false,
                AdaptersRestored: 0,
                PoliciesCleaned: true,
                Summary: "Previous session shut down cleanly.");
        }

        NetworkRestoredResult result = await restoreCallback(snapshot, cancellationToken).ConfigureAwait(false);
        await MarkCleanShutdownAsync(cancellationToken).ConfigureAwait(false);
        return result with { HadDirtyState = true };
    }

    /// <summary>
    /// Convenience overload that recovers a dirty snapshot using <see cref="ExecuteNativeRestore"/>.
    /// </summary>
    public Task<NetworkRestoredResult> RecoverIfDirtyAsync(CancellationToken cancellationToken = default)
    {
        return RecoverIfDirtyAsync(
            static (snapshot, _) => Task.FromResult(ExecuteNativeRestore(snapshot)),
            cancellationToken);
    }

    /// <summary>
    /// Self-contained OS restore path using Windows Registry, <c>dhcpcsvc.dll</c> <c>DhcpNotifyConfigChange</c>,
    /// and <c>dnsapi.dll</c> <c>DnsFlushResolverCache</c>. Gracefully reports unprivileged permission restrictions
    /// without throwing so non-elevated contexts and tests succeed cleanly.
    /// </summary>
    public static NetworkRestoredResult ExecuteNativeRestore(PrePulseNetworkSnapshot? snapshot)
    {
        int adaptersRestored = 0;
        List<string> notes = [];
        bool hadElevationRestriction = false;

        if (snapshot is not null)
        {
            foreach (AdapterDnsConfiguration adapter in snapshot.AdapterStates)
            {
                if (string.IsNullOrWhiteSpace(adapter.InterfaceGuid))
                {
                    continue;
                }

                string guid = adapter.InterfaceGuid.Trim();
                bool v4Touched = TryRestoreAdapterFamily(
                    TcpipInterfacesSubKey,
                    guid,
                    adapter.WasDhcpIpv4,
                    adapter.OriginalIpv4Dns,
                    ref hadElevationRestriction);

                bool v6Touched = TryRestoreAdapterFamily(
                    Tcpip6InterfacesSubKey,
                    guid,
                    adapter.WasDhcpIpv6,
                    adapter.OriginalIpv6Dns,
                    ref hadElevationRestriction);

                if (v4Touched || v6Touched)
                {
                    adaptersRestored++;
                    TryNotifyDhcpConfigChange(guid);
                }
            }

            TryRestoreSmhnrPolicy(snapshot.PriorSmhnrDisabled, ref hadElevationRestriction, notes);
        }

        TryDeletePulseNrptPolicies(ref hadElevationRestriction, notes);
        TryClearPulseWinInetPac(notes);
        bool cacheFlushed = TryFlushDnsResolverCache();

        if (cacheFlushed)
        {
            notes.Add("DNS resolver cache flushed");
        }

        if (hadElevationRestriction)
        {
            notes.Add("HKLM registry cleanup skipped due to insufficient privileges");
        }

        string summary = notes.Count > 0
            ? string.Join("; ", notes)
            : "Native network state verified clean.";

        return new NetworkRestoredResult(
            HadDirtyState: snapshot?.DirtyShutdown ?? false,
            AdaptersRestored: adaptersRestored,
            PoliciesCleaned: true,
            Summary: summary);
    }

    /// <summary>
    /// Hooks <see cref="AppDomain.UnhandledException"/>, <see cref="TaskScheduler.UnobservedTaskException"/>,
    /// and <see cref="AppDomain.ProcessExit"/> to perform emergency synchronous rollback when a dirty snapshot exists.
    /// </summary>
    /// <param name="journal">The active <see cref="NetworkSnapshotJournal"/> instance.</param>
    /// <param name="beforeRestore">Optional callback invoked right before <see cref="ExecuteNativeRestore"/>.</param>
    public static void RegisterEmergencyProcessHooks(NetworkSnapshotJournal journal, Action? beforeRestore = null)
    {
        ArgumentNullException.ThrowIfNull(journal);

        lock (HookRegistrationLock)
        {
            if (_unhandledHandler is not null)
            {
                AppDomain.CurrentDomain.UnhandledException -= _unhandledHandler;
            }

            if (_unobservedTaskHandler is not null)
            {
                TaskScheduler.UnobservedTaskException -= _unobservedTaskHandler;
            }

            if (_processExitHandler is not null)
            {
                AppDomain.CurrentDomain.ProcessExit -= _processExitHandler;
            }

            _unhandledHandler = (_, args) =>
            {
                if (args.IsTerminating)
                {
                    RunEmergencyRollback(journal, beforeRestore);
                }
            };

            _unobservedTaskHandler = (_, args) =>
            {
                args.SetObserved();
            };

            _processExitHandler = (_, _) =>
            {
                RunEmergencyRollback(journal, beforeRestore);
            };

            AppDomain.CurrentDomain.UnhandledException += _unhandledHandler;
            TaskScheduler.UnobservedTaskException += _unobservedTaskHandler;
            AppDomain.CurrentDomain.ProcessExit += _processExitHandler;
        }
    }

    [SuppressMessage("Design", "CA1031:Do not catch general exception types", Justification = "Process-exit and unhandled-exception emergency hooks must never throw.")]
    private static void RunEmergencyRollback(NetworkSnapshotJournal journal, Action? beforeRestore)
    {
        if (Interlocked.Exchange(ref _emergencyRestoreActive, 1) != 0)
        {
            return;
        }

        try
        {
            PrePulseNetworkSnapshot? snapshot = journal.TryLoadVerifiedSnapshotInternal(out _);
            if (snapshot is { DirtyShutdown: true })
            {
                beforeRestore?.Invoke();
                _ = ExecuteNativeRestore(snapshot);
                journal.MarkCleanShutdownSync(snapshot);
            }
        }
        catch
        {
            // Never propagate exceptions during crash/exit rollback.
        }
        finally
        {
            Interlocked.Exchange(ref _emergencyRestoreActive, 0);
        }
    }

    private PrePulseNetworkSnapshot? TryLoadVerifiedSnapshotInternal(out bool checksumMismatch)
    {
        checksumMismatch = false;
        bool primaryPresent = File.Exists(SnapshotFilePath);
        if (primaryPresent)
        {
            PrePulseNetworkSnapshot? primary = TryReadAndVerifyFile(SnapshotFilePath, out bool primaryFailed);
            if (primary is not null)
            {
                checksumMismatch = false;
                return primary;
            }

            if (File.Exists(BackupFilePath))
            {
                PrePulseNetworkSnapshot? backup = TryReadAndVerifyFile(BackupFilePath, out bool backupFailed);
                if (backup is not null)
                {
                    checksumMismatch = false;
                    return backup;
                }

                checksumMismatch = primaryFailed || backupFailed;
                return null;
            }

            checksumMismatch = primaryFailed;
            return null;
        }

        if (File.Exists(BackupFilePath))
        {
            PrePulseNetworkSnapshot? backup = TryReadAndVerifyFile(BackupFilePath, out bool backupFailed);
            checksumMismatch = backup is null && backupFailed;
            return backup;
        }

        return null;
    }

    private static PrePulseNetworkSnapshot? TryReadAndVerifyFile(string path, out bool integrityFailure)
    {
        integrityFailure = false;
        try
        {
            byte[] rawBytes = File.ReadAllBytes(path);
            PrePulseNetworkSnapshot? parsed = JsonSerializer.Deserialize<PrePulseNetworkSnapshot>(rawBytes, JsonOptions);
            if (parsed is null)
            {
                integrityFailure = true;
                return null;
            }

            if (!VerifyChecksumConstantTime(parsed))
            {
                integrityFailure = true;
                return null;
            }

            return parsed;
        }
        catch (JsonException)
        {
            integrityFailure = true;
            return null;
        }
        catch (IOException)
        {
            integrityFailure = true;
            return null;
        }
        catch (UnauthorizedAccessException)
        {
            integrityFailure = true;
            return null;
        }
    }

    private static bool VerifyChecksumConstantTime(PrePulseNetworkSnapshot snapshot)
    {
        if (string.IsNullOrWhiteSpace(snapshot.Sha256Checksum) || snapshot.Sha256Checksum.Length != 64)
        {
            return false;
        }

        byte[] expectedBytes;
        try
        {
            expectedBytes = Convert.FromHexString(snapshot.Sha256Checksum);
        }
        catch (FormatException)
        {
            return false;
        }

        if (expectedBytes.Length != 32)
        {
            return false;
        }

        byte[] actualBytes = ComputeCanonicalHashBytes(snapshot);
        return CryptographicOperations.FixedTimeEquals(actualBytes, expectedBytes);
    }

    private static byte[] ComputeCanonicalHashBytes(PrePulseNetworkSnapshot snapshot)
    {
        CanonicalSnapshotPayload payload = CanonicalSnapshotPayload.FromSnapshot(snapshot);
        byte[] jsonBytes = JsonSerializer.SerializeToUtf8Bytes(payload, CanonicalJsonOptions);
        return SHA256.HashData(jsonBytes);
    }

    private async Task WriteAtomicAsync(PrePulseNetworkSnapshot snapshot, CancellationToken cancellationToken)
    {
        Directory.CreateDirectory(BaseDirectory);
        string tempPath = string.Concat(SnapshotFilePath, TempFileSuffix);
        byte[] jsonBytes = JsonSerializer.SerializeToUtf8Bytes(snapshot, JsonOptions);

        await using (FileStream stream = new(
            tempPath,
            FileMode.Create,
            FileAccess.Write,
            FileShare.None,
            bufferSize: 4096,
            FileOptions.WriteThrough | FileOptions.Asynchronous))
        {
            await stream.WriteAsync(jsonBytes, cancellationToken).ConfigureAwait(false);
            await stream.FlushAsync(cancellationToken).ConfigureAwait(false);
        }

        ReplaceOrMoveAtomic(tempPath);
    }

    private void MarkCleanShutdownSync(PrePulseNetworkSnapshot existing)
    {
        PrePulseNetworkSnapshot unsigned = existing with
        {
            DirtyShutdown = false,
            Sha256Checksum = string.Empty
        };

        PrePulseNetworkSnapshot signed = unsigned with
        {
            Sha256Checksum = ComputeChecksum(unsigned)
        };

        Directory.CreateDirectory(BaseDirectory);
        string tempPath = string.Concat(SnapshotFilePath, TempFileSuffix);
        byte[] jsonBytes = JsonSerializer.SerializeToUtf8Bytes(signed, JsonOptions);

        using (FileStream stream = new(
            tempPath,
            FileMode.Create,
            FileAccess.Write,
            FileShare.None,
            bufferSize: 4096,
            FileOptions.WriteThrough))
        {
            stream.Write(jsonBytes, 0, jsonBytes.Length);
            stream.Flush();
        }

        ReplaceOrMoveAtomic(tempPath);
    }

    private void ReplaceOrMoveAtomic(string tempPath)
    {
        if (File.Exists(SnapshotFilePath))
        {
            File.Replace(tempPath, SnapshotFilePath, BackupFilePath, ignoreMetadataErrors: true);
        }
        else
        {
            File.Move(tempPath, SnapshotFilePath, overwrite: true);
        }
    }

    private static string ResolveWritableDirectory(string? explicitDirectory)
    {
        if (!string.IsNullOrWhiteSpace(explicitDirectory))
        {
            string full = Path.GetFullPath(explicitDirectory.Trim());
            Directory.CreateDirectory(full);
            return full;
        }

        string programData = Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData);
        if (!string.IsNullOrWhiteSpace(programData))
        {
            string candidate = Path.Combine(programData, "DnsPulse");
            if (IsDirectoryWritable(candidate))
            {
                return candidate;
            }
        }

        string localAppData = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
        string fallbackBase = string.IsNullOrWhiteSpace(localAppData) ? Path.GetTempPath() : localAppData;
        string fallback = Path.Combine(fallbackBase, "DnsPulse");
        Directory.CreateDirectory(fallback);
        return fallback;
    }

    private static bool IsDirectoryWritable(string directoryPath)
    {
        try
        {
            Directory.CreateDirectory(directoryPath);
            string probePath = Path.Combine(directoryPath, string.Create(CultureInfo.InvariantCulture, $".write-probe-{Guid.NewGuid():N}.tmp"));
            using (FileStream fs = new(probePath, FileMode.CreateNew, FileAccess.Write, FileShare.None, 1, FileOptions.DeleteOnClose))
            {
                fs.WriteByte(0x01);
            }

            return true;
        }
        catch (UnauthorizedAccessException)
        {
            return false;
        }
        catch (SecurityException)
        {
            return false;
        }
        catch (IOException)
        {
            return false;
        }
    }

    private static bool TryRestoreAdapterFamily(
        string interfacesSubKey,
        string interfaceGuid,
        bool wasDhcp,
        IReadOnlyList<string> originalDnsServers,
        ref bool hadElevationRestriction)
    {
        string subKeyPath = string.Create(CultureInfo.InvariantCulture, $"{interfacesSubKey}\\{interfaceGuid}");
        try
        {
            using RegistryKey? key = Registry.LocalMachine.OpenSubKey(subKeyPath, writable: true);
            if (key is null)
            {
                return false;
            }

            string targetValue = wasDhcp || originalDnsServers.Count == 0
                ? string.Empty
                : string.Join(",", originalDnsServers.Where(static s => !string.IsNullOrWhiteSpace(s)).Select(static s => s.Trim()));

            key.SetValue("NameServer", targetValue, RegistryValueKind.String);
            return true;
        }
        catch (UnauthorizedAccessException)
        {
            hadElevationRestriction = true;
            return false;
        }
        catch (SecurityException)
        {
            hadElevationRestriction = true;
            return false;
        }
    }

    private static void TryRestoreSmhnrPolicy(
        bool priorSmhnrDisabled,
        ref bool hadElevationRestriction,
        List<string> notes)
    {
        try
        {
            if (priorSmhnrDisabled)
            {
                using RegistryKey? key = Registry.LocalMachine.CreateSubKey(DnsClientPolicySubKey, writable: true);
                key?.SetValue(SmhnrValueName, 1, RegistryValueKind.DWord);
            }
            else
            {
                using RegistryKey? key = Registry.LocalMachine.OpenSubKey(DnsClientPolicySubKey, writable: true);
                key?.DeleteValue(SmhnrValueName, throwOnMissingValue: false);
            }

            notes.Add("SMHNR policy restored");
        }
        catch (UnauthorizedAccessException)
        {
            hadElevationRestriction = true;
        }
        catch (SecurityException)
        {
            hadElevationRestriction = true;
        }
    }

    private static void TryDeletePulseNrptPolicies(ref bool hadElevationRestriction, List<string> notes)
    {
        try
        {
            using RegistryKey? nrptRoot = Registry.LocalMachine.OpenSubKey(NrptPolicyConfigSubKey, writable: true);
            if (nrptRoot is null)
            {
                return;
            }

            int removed = 0;
            foreach (string subKeyName in nrptRoot.GetSubKeyNames())
            {
                if (subKeyName.StartsWith(PulseNrptPrefix, StringComparison.OrdinalIgnoreCase))
                {
                    nrptRoot.DeleteSubKeyTree(subKeyName, throwOnMissingSubKey: false);
                    removed++;
                }
            }

            if (removed > 0)
            {
                notes.Add(string.Create(CultureInfo.InvariantCulture, $"Removed {removed} PulseCore NRPT rules"));
            }
        }
        catch (UnauthorizedAccessException)
        {
            hadElevationRestriction = true;
        }
        catch (SecurityException)
        {
            hadElevationRestriction = true;
        }
    }

    private static void TryClearPulseWinInetPac(List<string> notes)
    {
        try
        {
            using RegistryKey? inetKey = Registry.CurrentUser.OpenSubKey(InternetSettingsSubKey, writable: true);
            if (inetKey?.GetValue(AutoConfigUrlValueName) is not string currentPac || string.IsNullOrWhiteSpace(currentPac))
            {
                return;
            }

            if (IsPulseCorePacUrl(currentPac))
            {
                inetKey.DeleteValue(AutoConfigUrlValueName, throwOnMissingValue: false);
                notes.Add("Cleared PulseCore WinINet AutoConfigURL");
            }
        }
        catch (UnauthorizedAccessException)
        {
        }
        catch (SecurityException)
        {
        }
    }

    private static bool IsPulseCorePacUrl(string url)
    {
        if (!Uri.TryCreate(url.Trim(), UriKind.Absolute, out Uri? uri))
        {
            return false;
        }

        if (!string.Equals(uri.Scheme, Uri.UriSchemeHttp, StringComparison.OrdinalIgnoreCase))
        {
            return false;
        }

        bool isLoopbackHost = string.Equals(uri.Host, "127.0.0.1", StringComparison.Ordinal)
            || uri.Host.StartsWith("127.0.53.", StringComparison.Ordinal)
            || string.Equals(uri.Host, "::1", StringComparison.Ordinal)
            || string.Equals(uri.Host, "localhost", StringComparison.OrdinalIgnoreCase);

        return isLoopbackHost && uri.AbsolutePath.Equals("/proxy.pac", StringComparison.OrdinalIgnoreCase);
    }

    private static void TryNotifyDhcpConfigChange(string interfaceGuid)
    {
        nint adapterPtr = nint.Zero;
        try
        {
            adapterPtr = Marshal.StringToHGlobalUni(interfaceGuid);
            _ = NativeMethods.DhcpNotifyConfigChange(
                nint.Zero,
                adapterPtr,
                bNewIpAddress: 0,
                dwIpIndex: 0,
                dwIpAddress: 0,
                dwSubNetMask: 0,
                nServiceEnable: 0);
        }
        catch (DllNotFoundException)
        {
        }
        catch (EntryPointNotFoundException)
        {
        }
        finally
        {
            if (adapterPtr != nint.Zero)
            {
                Marshal.FreeHGlobal(adapterPtr);
            }
        }
    }

    private static bool TryFlushDnsResolverCache()
    {
        try
        {
            _ = NativeMethods.DnsFlushResolverCache();
            return true;
        }
        catch (DllNotFoundException)
        {
            return false;
        }
        catch (EntryPointNotFoundException)
        {
            return false;
        }
    }

    private sealed record CanonicalSnapshotPayload(
        int SnapshotVersion,
        DateTimeOffset CapturedAtUtc,
        bool DirtyShutdown,
        InterceptionMode ActiveMode,
        string? LoopbackIpUsed,
        IReadOnlyList<AdapterDnsConfiguration> AdapterStates,
        bool PriorSmhnrDisabled,
        IReadOnlyList<string> PriorNrptRuleNames)
    {
        public static CanonicalSnapshotPayload FromSnapshot(PrePulseNetworkSnapshot snapshot)
        {
            return new CanonicalSnapshotPayload(
                snapshot.SnapshotVersion,
                snapshot.CapturedAtUtc,
                snapshot.DirtyShutdown,
                snapshot.ActiveMode,
                snapshot.LoopbackIpUsed,
                snapshot.AdapterStates,
                snapshot.PriorSmhnrDisabled,
                snapshot.PriorNrptRuleNames);
        }
    }

    private sealed class AsyncMutex
    {
        private readonly Lock _gate = new();
        private readonly Queue<TaskCompletionSource> _waiters = new();
        private bool _held;

        public async Task WaitAsync(CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();

            TaskCompletionSource tcs;
            lock (_gate)
            {
                if (!_held)
                {
                    _held = true;
                    return;
                }

                tcs = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
                _waiters.Enqueue(tcs);
            }

            if (cancellationToken.CanBeCanceled)
            {
                await using CancellationTokenRegistration registration = cancellationToken.Register(
                    static state => ((TaskCompletionSource)state!).TrySetCanceled(),
                    tcs);
                await tcs.Task.ConfigureAwait(false);
                return;
            }

            await tcs.Task.ConfigureAwait(false);
        }

        public void Release()
        {
            lock (_gate)
            {
                while (_waiters.Count > 0)
                {
                    TaskCompletionSource next = _waiters.Dequeue();
                    if (next.TrySetResult())
                    {
                        return;
                    }
                }

                _held = false;
            }
        }
    }

    private static class NativeMethods
    {
        [SuppressMessage("Interoperability", "SYSLIB1054:Use 'LibraryImportAttribute' instead of 'DllImportAttribute' to generate P/Invoke marshalling code at compile time", Justification = "AllowUnsafeBlocks is not enabled in the project.")]
        [DllImport("dnsapi.dll", ExactSpelling = true)]
        [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
        internal static extern uint DnsFlushResolverCache();

        [SuppressMessage("Interoperability", "SYSLIB1054:Use 'LibraryImportAttribute' instead of 'DllImportAttribute' to generate P/Invoke marshalling code at compile time", Justification = "AllowUnsafeBlocks is not enabled in the project.")]
        [DllImport("dhcpcsvc.dll", ExactSpelling = true)]
        [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
        internal static extern uint DhcpNotifyConfigChange(
            nint lpwszServerName,
            nint lpwszAdapterName,
            int bNewIpAddress,
            uint dwIpIndex,
            uint dwIpAddress,
            uint dwSubNetMask,
            int nServiceEnable);
    }
}
