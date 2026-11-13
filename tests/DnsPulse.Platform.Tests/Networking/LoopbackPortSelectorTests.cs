using System.Net;
using System.Net.Sockets;
using DnsPulse.Platform.Windows.Networking;
using FluentAssertions;

namespace DnsPulse.Platform.Tests.Networking;

public sealed class LoopbackPortSelectorTests
{
    [Fact]
    public void SelectAvailableDnsEndpoint_ReturnsLoopback_WhenEphemeralPortIsFree()
    {
        int freePort = GetFreeEphemeralPort();
        LoopbackPortSelector selector = new();

        IPAddress selected = selector.SelectAvailableDnsEndpoint(freePort);

        selected.Should().Be(IPAddress.Loopback);
    }

    [Fact]
    public void SelectAvailableDnsEndpoint_FallsBackTo1270531_WhenPrimaryLoopbackIsOccupied()
    {
        int port = GetFreeEphemeralPort();
        using Socket occupant = new(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
        occupant.ExclusiveAddressUse = true;
        occupant.Bind(new IPEndPoint(IPAddress.Loopback, port));

        LoopbackPortSelector selector = new();
        IPAddress selected = selector.SelectAvailableDnsEndpoint(port);

        selected.Should().Be(IPAddress.Parse("127.0.53.1"));
    }

    [Theory]
    [InlineData(0)]
    [InlineData(-1)]
    [InlineData(65536)]
    public void SelectAvailableDnsEndpoint_ThrowsForOutOfRangePort(int invalidPort)
    {
        LoopbackPortSelector selector = new();

        Action act = () => selector.SelectAvailableDnsEndpoint(invalidPort);

        act.Should().Throw<ArgumentOutOfRangeException>();
    }

    private static int GetFreeEphemeralPort()
    {
        using Socket probe = new(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
        probe.Bind(new IPEndPoint(IPAddress.Loopback, 0));
        return ((IPEndPoint)probe.LocalEndPoint!).Port;
    }
}
