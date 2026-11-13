using System.Net;
using DnsPulse.Platform.Windows.Contracts;
using DnsPulse.Platform.Windows.Recovery;
using FluentAssertions;

namespace DnsPulse.Platform.Tests.Recovery;

public sealed class NetworkSnapshotJournalTests : IDisposable
{
    private readonly string _tempDir;

    public NetworkSnapshotJournalTests()
    {
        _tempDir = Path.Combine(Path.GetTempPath(), "DnsPulseTests", "Recovery", Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(_tempDir);
    }

    [Fact]
    public async Task BeginTransactionAndMarkCleanShutdown_AtomicTmpAndBakRoundtrip_Succeeds()
    {
        NetworkSnapshotJournal journal = new(_tempDir);
        AdapterDnsConfiguration[] adapters =
        [
            new AdapterDnsConfiguration
            {
                InterfaceGuid = "{11111111-2222-3333-4444-555555555555}",
                InterfaceName = "Ethernet",
                InterfaceDescription = "Test Adapter",
                OriginalIpv4Dns = ["8.8.8.8", "1.1.1.1"],
                OriginalIpv6Dns = [],
                WasDhcpIpv4 = false,
                WasDhcpIpv6 = true,
                IsPhysicalUp = true
            }
        ];

        PrePulseNetworkSnapshot dirty = await journal.BeginTransactionAsync(
            InterceptionMode.AdapterDns,
            IPAddress.Parse("127.0.53.1"),
            adapters,
            priorSmhnrDisabled: true,
            priorNrptRules: ["CorpRule"]);

        dirty.DirtyShutdown.Should().BeTrue();
        dirty.Sha256Checksum.Should().HaveLength(64);
        File.Exists(journal.SnapshotFilePath).Should().BeTrue();
        File.Exists(string.Concat(journal.SnapshotFilePath, ".tmp")).Should().BeFalse();

        PrePulseNetworkSnapshot? loadedDirty = journal.TryLoadVerifiedSnapshot(out bool mismatch1);
        mismatch1.Should().BeFalse();
        loadedDirty.Should().NotBeNull();
        loadedDirty!.DirtyShutdown.Should().BeTrue();
        loadedDirty.LoopbackIpUsed.Should().Be("127.0.53.1");
        loadedDirty.PriorSmhnrDisabled.Should().BeTrue();
        loadedDirty.PriorNrptRuleNames.Should().ContainSingle().Which.Should().Be("CorpRule");
        loadedDirty.AdapterStates.Should().HaveCount(1);

        bool markedClean = await journal.MarkCleanShutdownAsync();
        markedClean.Should().BeTrue();
        File.Exists(journal.BackupFilePath).Should().BeTrue();
        File.Exists(string.Concat(journal.SnapshotFilePath, ".tmp")).Should().BeFalse();

        PrePulseNetworkSnapshot? loadedClean = journal.TryLoadVerifiedSnapshot(out bool mismatch2);
        mismatch2.Should().BeFalse();
        loadedClean.Should().NotBeNull();
        loadedClean!.DirtyShutdown.Should().BeFalse();
        loadedClean.Sha256Checksum.Should().NotBe(dirty.Sha256Checksum);
    }

    [Fact]
    public async Task TryLoadVerifiedSnapshot_TamperedPrimaryWithoutBackup_SetsChecksumMismatchAndReturnsNull()
    {
        NetworkSnapshotJournal journal = new(_tempDir);
        await journal.BeginTransactionAsync(
            InterceptionMode.SplitNrpt,
            IPAddress.Loopback,
            [],
            priorSmhnrDisabled: false,
            priorNrptRules: []);

        string json = await File.ReadAllTextAsync(journal.SnapshotFilePath);
        string tamperedJson = json.Replace("127.0.0.1", "127.0.53.9", StringComparison.Ordinal);
        await File.WriteAllTextAsync(journal.SnapshotFilePath, tamperedJson);

        PrePulseNetworkSnapshot? loaded = journal.TryLoadVerifiedSnapshot(out bool checksumMismatch);

        checksumMismatch.Should().BeTrue();
        loaded.Should().BeNull();
    }

    [Fact]
    public async Task TryLoadVerifiedSnapshot_CorruptedPrimaryWithValidBackup_RecoversFromBak()
    {
        NetworkSnapshotJournal journal = new(_tempDir);
        PrePulseNetworkSnapshot first = await journal.BeginTransactionAsync(
            InterceptionMode.AdapterDns,
            IPAddress.Parse("127.0.53.2"),
            [],
            priorSmhnrDisabled: false,
            priorNrptRules: []);

        await journal.MarkCleanShutdownAsync();
        File.Exists(journal.BackupFilePath).Should().BeTrue();

        // Corrupt primary snapshot on disk while .bak remains intact and signed
        await File.WriteAllTextAsync(journal.SnapshotFilePath, "{ invalid json");

        PrePulseNetworkSnapshot? recovered = journal.TryLoadVerifiedSnapshot(out bool mismatchWithValidBak);
        mismatchWithValidBak.Should().BeFalse();
        recovered.Should().NotBeNull();
        recovered!.Sha256Checksum.Should().Be(first.Sha256Checksum);
        recovered.DirtyShutdown.Should().BeTrue();

        // Now tamper .bak as well -> both fail verification
        await File.WriteAllTextAsync(journal.BackupFilePath, "{ tampered backup");
        PrePulseNetworkSnapshot? rejected = journal.TryLoadVerifiedSnapshot(out bool mismatchBothBad);
        mismatchBothBad.Should().BeTrue();
        rejected.Should().BeNull();
    }

    [Fact]
    public async Task RecoverIfDirtyAsync_SimulatedCrash_TriggersCallbackAndClearsDirtyShutdown()
    {
        NetworkSnapshotJournal writerJournal = new(_tempDir);
        AdapterDnsConfiguration[] adapters =
        [
            new AdapterDnsConfiguration
            {
                InterfaceGuid = "{AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE}",
                InterfaceName = "Wi-Fi",
                WasDhcpIpv4 = true,
                WasDhcpIpv6 = true,
                IsPhysicalUp = true
            }
        ];

        await writerJournal.BeginTransactionAsync(
            InterceptionMode.AdapterDns,
            IPAddress.Parse("127.0.53.1"),
            adapters,
            priorSmhnrDisabled: false,
            priorNrptRules: []);

        // Simulate fresh process startup with a new journal instance
        NetworkSnapshotJournal recoveryJournal = new(_tempDir);
        int callbackInvocations = 0;
        PrePulseNetworkSnapshot? observedSnapshot = null;

        NetworkRestoredResult result = await recoveryJournal.RecoverIfDirtyAsync((snapshot, _) =>
        {
            callbackInvocations++;
            observedSnapshot = snapshot;
            return Task.FromResult(new NetworkRestoredResult(
                HadDirtyState: true,
                AdaptersRestored: snapshot.AdapterStates.Count,
                PoliciesCleaned: true,
                Summary: "Restored in test callback"));
        });

        callbackInvocations.Should().Be(1);
        observedSnapshot.Should().NotBeNull();
        observedSnapshot!.AdapterStates.Should().HaveCount(1);
        result.HadDirtyState.Should().BeTrue();
        result.AdaptersRestored.Should().Be(1);
        result.PoliciesCleaned.Should().BeTrue();

        PrePulseNetworkSnapshot? afterRecovery = recoveryJournal.TryLoadVerifiedSnapshot(out bool mismatch);
        mismatch.Should().BeFalse();
        afterRecovery.Should().NotBeNull();
        afterRecovery!.DirtyShutdown.Should().BeFalse();

        // Second recovery pass should be a no-op
        NetworkRestoredResult secondResult = await recoveryJournal.RecoverIfDirtyAsync((_, _) =>
        {
            callbackInvocations++;
            return Task.FromResult(new NetworkRestoredResult(true, 0, true, "Should not run"));
        });

        callbackInvocations.Should().Be(1);
        secondResult.HadDirtyState.Should().BeFalse();
    }

    [Fact]
    public void ComputeChecksum_ExcludesSha256ChecksumProperty()
    {
        PrePulseNetworkSnapshot baseSnapshot = new()
        {
            SnapshotVersion = 1,
            CapturedAtUtc = new DateTimeOffset(2026, 11, 14, 1, 0, 0, TimeSpan.Zero),
            DirtyShutdown = true,
            ActiveMode = InterceptionMode.LocalProxyPacOnly,
            LoopbackIpUsed = "127.0.53.1",
            AdapterStates = [],
            PriorSmhnrDisabled = true,
            PriorNrptRuleNames = ["RuleA"],
            Sha256Checksum = string.Empty
        };

        PrePulseNetworkSnapshot withDifferentChecksum = baseSnapshot with
        {
            Sha256Checksum = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
        };

        string hash1 = NetworkSnapshotJournal.ComputeChecksum(baseSnapshot);
        string hash2 = NetworkSnapshotJournal.ComputeChecksum(withDifferentChecksum);

        hash1.Should().HaveLength(64);
        hash1.Should().Be(hash2);
    }

    [Fact]
    public void ExecuteNativeRestore_WithNullSnapshot_CompletesGracefullyWithoutThrowing()
    {
        NetworkRestoredResult result = NetworkSnapshotJournal.ExecuteNativeRestore(null);

        result.PoliciesCleaned.Should().BeTrue();
        result.Summary.Should().NotBeNullOrWhiteSpace();
    }

    public void Dispose()
    {
        try
        {
            if (Directory.Exists(_tempDir))
            {
                Directory.Delete(_tempDir, recursive: true);
            }
        }
        catch (IOException)
        {
        }
        catch (UnauthorizedAccessException)
        {
        }
    }
}
