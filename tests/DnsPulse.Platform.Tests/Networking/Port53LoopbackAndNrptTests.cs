using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using DnsPulse.Platform.Windows.Interception;
using DnsPulse.Platform.Windows.Networking;
using DnsPulse.Platform.Windows.Updates;
using FluentAssertions;

namespace DnsPulse.Platform.Tests.Networking;

public sealed class Port53LoopbackAndNrptTests
{
    [Fact]
    public void Port53ConflictInspector_IgnoresUnrelatedLoopbackIp127_0_0_53_AndRespectsSpecificEndpoint()
    {
        IPAddress unrelatedLoopback = IPAddress.Parse("127.0.0.53");
        using TcpListener unrelatedListener = new(unrelatedLoopback, 0);
        unrelatedListener.Start();
        int testPort = ((IPEndPoint)unrelatedListener.LocalEndpoint).Port;

        Port53ConflictInspector inspector = new();

        (string? defaultOccupant, int? defaultPid) = inspector.InspectPortConflict(testPort, excludeSelfProcesses: false);
        defaultOccupant.Should().BeNull("127.0.0.53 does not conflict with 127.0.0.1 or 127.0.53.x");
        defaultPid.Should().BeNull();

        (string? blockingOccupant, int? blockingPid) = inspector.InspectBlockingPortConflict(testPort, excludeSelfProcesses: false);
        blockingOccupant.Should().BeNull();
        blockingPid.Should().BeNull();

        (string? specificOccupant, int? specificPid) = inspector.InspectPortConflict(testPort, unrelatedLoopback, excludeSelfProcesses: false);
        specificOccupant.Should().NotBeNullOrWhiteSpace();
        specificPid.Should().Be(Environment.ProcessId);
    }

    [Fact]
    public void LoopbackPortSelector_Selects127_0_53_1_When127_0_0_1_IsOccupied()
    {
        using TcpListener primaryListener = new(IPAddress.Loopback, 0);
        primaryListener.Start();
        int testPort = ((IPEndPoint)primaryListener.LocalEndpoint).Port;

        LoopbackPortSelector selector = new();
        bool found = selector.TrySelectAvailableDnsEndpoint(testPort, out IPAddress? selectedAddress);

        found.Should().BeTrue();
        selectedAddress.Should().NotBeNull();
        selectedAddress.Should().NotBe(IPAddress.Loopback);
        selectedAddress!.ToString().Should().StartWith("127.0.53.");
    }

    [Fact]
    public void Port53ConflictInspector_DoesNotReportBlockingConflict_WhenOnly127_0_0_1_IsOccupied()
    {
        using TcpListener primaryListener = new(IPAddress.Loopback, 0);
        primaryListener.Start();
        int testPort = ((IPEndPoint)primaryListener.LocalEndpoint).Port;

        Port53ConflictInspector inspector = new();
        (string? blockingOccupant, int? blockingPid) = inspector.InspectBlockingPortConflict(testPort, excludeSelfProcesses: false);

        blockingOccupant.Should().BeNull("127.0.53.1..10 remain available");
        blockingPid.Should().BeNull();
    }

    [Fact]
    public void NrptPolicyManager_ThrowsNotSupportedException_WhenPortIsNot53()
    {
        Action act = () => NrptPolicyManager.ApplySplitRules(IPAddress.Loopback, 5353, ["chatgpt.com"]);
        act.Should().Throw<NotSupportedException>();
    }

    [Fact]
    public void LocalProxyPacInterceptor_UpdatePacUrl_UpdatesConfiguredPacUrlProperty()
    {
        LocalProxyPacInterceptor interceptor = new();
        interceptor.ConfiguredPacUrl.Should().BeNull();
        interceptor.ActivePacUrl.Should().BeNull();

        interceptor.UpdatePacUrl("http://127.0.0.1:41234/proxy.pac");
        interceptor.ConfiguredPacUrl.Should().Be("http://127.0.0.1:41234/proxy.pac");
    }

    [Fact]
    public void VerifiedAppUpdateService_CreateSilentInstallerStartInfo_HonorsElevationFlag()
    {
        string fakeInstaller = Path.Combine(Path.GetTempPath(), $"DnsPulse-Setup-{Guid.NewGuid():N}.exe");
        File.WriteAllBytes(fakeInstaller, [0x4D, 0x5A]);

        try
        {
            ProcessStartInfo elevated = VerifiedAppUpdateService.CreateSilentInstallerStartInfo(fakeInstaller, requireElevation: true);
            elevated.UseShellExecute.Should().BeTrue();
            elevated.Verb.Should().Be("runas");
            elevated.Arguments.Should().Contain("/VERYSILENT");

            ProcessStartInfo nonElevated = VerifiedAppUpdateService.CreateSilentInstallerStartInfo(fakeInstaller, requireElevation: false);
            nonElevated.UseShellExecute.Should().BeTrue();
            nonElevated.Verb.Should().BeEmpty();
            nonElevated.Arguments.Should().Contain("/VERYSILENT");
        }
        finally
        {
            if (File.Exists(fakeInstaller))
            {
                File.Delete(fakeInstaller);
            }
        }
    }
}
