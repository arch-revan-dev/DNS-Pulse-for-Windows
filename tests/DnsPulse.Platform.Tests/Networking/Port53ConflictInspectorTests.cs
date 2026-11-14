using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using DnsPulse.Platform.Windows.Networking;
using FluentAssertions;

namespace DnsPulse.Platform.Tests.Networking;

public sealed class Port53ConflictInspectorTests
{
    [Fact]
    public void InspectPortConflict_DetectsCurrentProcessOnLiveUdpSocket()
    {
        using Socket udpSocket = new(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
        udpSocket.ExclusiveAddressUse = true;
        udpSocket.Bind(new IPEndPoint(IPAddress.Loopback, 0));
        int boundPort = ((IPEndPoint)udpSocket.LocalEndPoint!).Port;

        Port53ConflictInspector inspector = new();
        (string? occupantName, int? processId) = inspector.InspectPortConflict(boundPort);

        using Process currentProcess = Process.GetCurrentProcess();
        processId.Should().Be(Environment.ProcessId);
        occupantName.Should().Be(currentProcess.ProcessName);
    }

    [Fact]
    public void InspectPortConflict_ReturnsNull_WhenPortIsUnbound()
    {
        int unboundPort;
        using (Socket probe = new(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp))
        {
            probe.Bind(new IPEndPoint(IPAddress.Loopback, 0));
            unboundPort = ((IPEndPoint)probe.LocalEndPoint!).Port;
        }

        Port53ConflictInspector inspector = new();
        (string? occupantName, int? processId) = inspector.InspectPortConflict(unboundPort);

        occupantName.Should().BeNull();
        processId.Should().BeNull();
    }

    [Theory]
    [InlineData("DnsPulse", true)]
    [InlineData("DnsPulse.exe", true)]
    [InlineData("DnsPulse.Service", true)]
    [InlineData("DnsPulse.Service.exe", true)]
    [InlineData("DnsPulse.App", true)]
    [InlineData("DnsPulse-2.0.3-win-x64.exe", true)]
    [InlineData("ag_dns", false)]
    [InlineData("dnscrypt-proxy.exe", false)]
    [InlineData("testhost", false)]
    [InlineData("", false)]
    [InlineData(null, false)]
    public void IsSelfProcessName_MatchesOnlyDnsPulseProcesses(string? processName, bool expected)
    {
        Port53ConflictInspector.IsSelfProcessName(processName).Should().Be(expected);
    }

    [Fact]
    public async Task HostNetworkHealthProvider_SkipsPort53Check_WhenDesiredDnsPortIsAuto()
    {
        HostNetworkHealthProvider provider = new(
            enableOsProbes: true,
            desiredDnsPortProvider: static () => 0);

        var snapshot = await provider.InspectAsync();

        snapshot.Port53OccupantName.Should().BeNull();
        snapshot.Port53OccupantProcessId.Should().BeNull();
    }
}
