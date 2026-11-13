using System.Globalization;
using System.Text.Json;
using DnsPulse.Engine.Contracts;
using DnsPulse.Platform.Windows.Contracts;
using DnsPulse.Platform.Windows.Ipc;
using DnsPulse.Service;
using FluentAssertions;

namespace DnsPulse.Platform.Tests.Ipc;

public sealed class DeadMansWatchdogTests
{
    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        PropertyNameCaseInsensitive = true
    };

    [Fact]
    public async Task Watchdog_TriggersEmergencyRestore_WhenConnectedListenerStaysUnhealthyPastThreshold()
    {
        FakeRuntimeBackend backend = new()
        {
            IsConnected = true,
            ProbeHealthyResult = false,
            DirtyRecoveryPending = true
        };

        string pipeName = CreateUniquePipeName();
        PulseServiceOptions options = new()
        {
            PipeName = pipeName,
            HealthCheckInterval = TimeSpan.FromMilliseconds(30),
            UnhealthyRollbackThreshold = TimeSpan.FromMilliseconds(200)
        };

        using DnsPulseWorkerService worker = new(backend, options);
        await worker.StartAsync(CancellationToken.None);
        try
        {
            await backend.WaitForEmergencyRestoreAsync(TimeSpan.FromSeconds(5));

            backend.EmergencyRestoreCalls.Should().Be(1);
            backend.IsConnected.Should().BeFalse();

            ServiceStatusSnapshot effectiveStatus = worker.GetStatus();
            effectiveStatus.IsConnected.Should().BeFalse();
            effectiveStatus.DirtyRecoveryPending.Should().BeFalse();
            effectiveStatus.LastErrorMessage.Should().NotBeNullOrWhiteSpace();

            // Verify the updated status is also surfaced cleanly over the hardened Named Pipe.
            PulsePipeIpcClient client = new(pipeName);
            PipeRpcResponse ipcResponse = await client.SendAsync(new PipeRpcRequest("status-1", PipeCommandNames.GetStatus));
            ipcResponse.Success.Should().BeTrue();
            ServiceStatusSnapshot? ipcStatus = JsonSerializer.Deserialize<ServiceStatusSnapshot>(ipcResponse.PayloadJson!, JsonOptions);
            ipcStatus.Should().NotBeNull();
            ipcStatus!.DirtyRecoveryPending.Should().BeFalse();
            ipcStatus.LastErrorMessage.Should().NotBeNullOrWhiteSpace();
        }
        finally
        {
            await worker.StopAsync(CancellationToken.None);
        }
    }

    [Fact]
    public async Task Watchdog_DoesNotRollback_WhenProbeRecoversBeforeThreshold()
    {
        FakeRuntimeBackend backend = new()
        {
            IsConnected = true,
            ProbeHealthyResult = false
        };

        PulseServiceOptions options = new()
        {
            PipeName = CreateUniquePipeName(),
            HealthCheckInterval = TimeSpan.FromMilliseconds(30),
            UnhealthyRollbackThreshold = TimeSpan.FromMilliseconds(500)
        };

        using DnsPulseWorkerService worker = new(backend, options);
        await worker.StartAsync(CancellationToken.None);
        try
        {
            await Task.Delay(120);
            backend.ProbeHealthyResult = true;
            await Task.Delay(550);

            backend.EmergencyRestoreCalls.Should().Be(0);
            backend.IsConnected.Should().BeTrue();
        }
        finally
        {
            await worker.StopAsync(CancellationToken.None);
        }
    }

    [Fact]
    public async Task StopAsync_CallsDisconnectCleanly_AndFallsBackToEmergencyRestoreIfDisconnectFails()
    {
        FakeRuntimeBackend cleanBackend = new()
        {
            IsConnected = true,
            ProbeHealthyResult = true
        };

        PulseServiceOptions cleanOptions = new()
        {
            PipeName = CreateUniquePipeName(),
            HealthCheckInterval = TimeSpan.FromMilliseconds(100),
            UnhealthyRollbackThreshold = TimeSpan.FromSeconds(10)
        };

        using (DnsPulseWorkerService cleanWorker = new(cleanBackend, cleanOptions))
        {
            await cleanWorker.StartAsync(CancellationToken.None);
            await cleanWorker.StopAsync(CancellationToken.None);
        }

        cleanBackend.DisconnectCalls.Should().Be(1);
        cleanBackend.IsConnected.Should().BeFalse();

        FakeRuntimeBackend failingDisconnectBackend = new()
        {
            IsConnected = true,
            ProbeHealthyResult = true,
            ThrowOnDisconnect = true
        };

        PulseServiceOptions fallbackOptions = new()
        {
            PipeName = CreateUniquePipeName(),
            HealthCheckInterval = TimeSpan.FromMilliseconds(100),
            UnhealthyRollbackThreshold = TimeSpan.FromSeconds(10)
        };

        using (DnsPulseWorkerService fallbackWorker = new(failingDisconnectBackend, fallbackOptions))
        {
            await fallbackWorker.StartAsync(CancellationToken.None);
            await fallbackWorker.StopAsync(CancellationToken.None);
        }

        failingDisconnectBackend.DisconnectCalls.Should().Be(1);
        failingDisconnectBackend.EmergencyRestoreCalls.Should().Be(1);
        failingDisconnectBackend.IsConnected.Should().BeFalse();
    }

    private static string CreateUniquePipeName()
    {
        return string.Create(CultureInfo.InvariantCulture, $"DnsPulse.WatchdogTest.{Guid.NewGuid():N}");
    }

    private sealed class FakeRuntimeBackend : IPulseRuntimeBackend
    {
        private readonly TaskCompletionSource<bool> _emergencyRestoreTcs =
            new(TaskCreationOptions.RunContinuationsAsynchronously);

        private int _disconnectCalls;
        private int _emergencyRestoreCalls;

        public bool IsConnected { get; set; }

        public bool ProbeHealthyResult { get; set; }

        public bool DirtyRecoveryPending { get; set; }

        public bool ThrowOnDisconnect { get; set; }

        public string? LastErrorMessage { get; set; }

        public int DisconnectCalls => Volatile.Read(ref _disconnectCalls);

        public int EmergencyRestoreCalls => Volatile.Read(ref _emergencyRestoreCalls);

        public ServiceStatusSnapshot GetStatus()
        {
            return new ServiceStatusSnapshot
            {
                IsConnected = IsConnected,
                IsHealthy = IsConnected && ProbeHealthyResult,
                ActiveMode = IsConnected ? InterceptionMode.AdapterDns : InterceptionMode.None,
                DirtyRecoveryPending = DirtyRecoveryPending,
                LastErrorMessage = LastErrorMessage
            };
        }

        public Task<ServiceStatusSnapshot> ConnectAsync(CancellationToken cancellationToken = default)
        {
            IsConnected = true;
            return Task.FromResult(GetStatus());
        }

        public Task<ServiceStatusSnapshot> DisconnectAsync(CancellationToken cancellationToken = default)
        {
            Interlocked.Increment(ref _disconnectCalls);
            if (ThrowOnDisconnect)
            {
                throw new InvalidOperationException("Simulated disconnect failure.");
            }

            IsConnected = false;
            return Task.FromResult(GetStatus());
        }

        public Task<NetworkRestoredResult> EmergencyRestoreAsync(CancellationToken cancellationToken = default)
        {
            Interlocked.Increment(ref _emergencyRestoreCalls);
            IsConnected = false;
            DirtyRecoveryPending = false;
            LastErrorMessage = "Emergency rollback completed.";
            NetworkRestoredResult result = new(
                HadDirtyState: true,
                AdaptersRestored: 1,
                PoliciesCleaned: true,
                Summary: "Restored host DNS configuration.");
            _emergencyRestoreTcs.TrySetResult(true);
            return Task.FromResult(result);
        }

        public IReadOnlyList<DnsQueryTelemetryEvent> GetRecentTelemetry(int maxCount = 100)
        {
            return [];
        }

        public Task<bool> ProbeListenerHealthAsync(CancellationToken cancellationToken = default)
        {
            return Task.FromResult(ProbeHealthyResult);
        }

        public async Task WaitForEmergencyRestoreAsync(TimeSpan timeout)
        {
            using CancellationTokenSource cts = new(timeout);
            await _emergencyRestoreTcs.Task.WaitAsync(cts.Token);
        }
    }
}
