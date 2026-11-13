using DnsPulse.Engine.Contracts;
using DnsPulse.Platform.Windows.Networking;
using FluentAssertions;

namespace DnsPulse.Platform.Tests.Networking;

public sealed class HostNetworkHealthProviderTests
{
    [Fact]
    public async Task InspectAsync_ReturnsCleanEmptySnapshot_WhenOsProbesDisabled()
    {
        HostNetworkHealthProvider provider = new(enableOsProbes: false);

        HostNetworkHealthSnapshot snapshot = await provider.InspectAsync();

        snapshot.ActiveInterfaceNames.Should().BeEmpty();
        snapshot.HasIpv4Connectivity.Should().BeFalse();
        snapshot.HasIpv6Connectivity.Should().BeFalse();
        snapshot.IsCaptivePortalDetected.Should().BeFalse();
        snapshot.Port53OccupantName.Should().BeNull();
        snapshot.Port53OccupantProcessId.Should().BeNull();
        snapshot.IsSmhnrDisabled.Should().BeFalse();
        snapshot.DetectedBrowserDohBypassBrowsers.Should().BeEmpty();
    }

    [Fact]
    public async Task InspectAsync_ReturnsValidSnapshot_WhenOsProbesEnabled()
    {
        HostNetworkHealthProvider provider = new(enableOsProbes: true);

        HostNetworkHealthSnapshot snapshot = await provider.InspectAsync();

        snapshot.CapturedAtUtc.Should().BeCloseTo(DateTimeOffset.UtcNow, TimeSpan.FromMinutes(1));
        snapshot.ActiveInterfaceNames.Should().NotBeNull();
        snapshot.DetectedBrowserDohBypassBrowsers.Should().NotBeNull();
    }

    [Fact]
    public async Task InspectAsync_HonorsCancellationToken()
    {
        HostNetworkHealthProvider provider = new(enableOsProbes: false);
        using CancellationTokenSource cts = new();
        await cts.CancelAsync();

        Func<Task> act = () => provider.InspectAsync(cts.Token);

        await act.Should().ThrowAsync<OperationCanceledException>();
    }
}
