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
}
