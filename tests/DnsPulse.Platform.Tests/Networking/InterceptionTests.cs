using System.Net;
using DnsPulse.Platform.Windows.Contracts;
using DnsPulse.Platform.Windows.Interception;
using FluentAssertions;

namespace DnsPulse.Platform.Tests.Networking;

public sealed class InterceptionTests
{
    [Fact]
    public async Task WfpDivertInterceptor_BlocksActivation_WhenAntiCheatIsActive()
    {
        string[] activeAntiCheat = ["vgc", "vgtray"];
        WfpDivertInterceptor interceptor = new(() => (true, activeAntiCheat));
        string[] domains = ["example.com"];

        Func<Task> act = () => interceptor.ActivateAsync(IPAddress.Loopback, 53, domains);

        await act.Should().ThrowAsync<InvalidOperationException>();
        interceptor.Mode.Should().Be(InterceptionMode.WfpDivertPlugin);
        interceptor.IsPausedForAntiCheat.Should().BeTrue();
        interceptor.BlockedByAntiCheatNames.Should().Equal("vgc", "vgtray");

        await interceptor.DeactivateAsync();
        interceptor.IsPausedForAntiCheat.Should().BeFalse();
        interceptor.BlockedByAntiCheatNames.Should().BeEmpty();
    }

    [Fact]
    public async Task AdapterDnsInterceptor_RejectsNon53DnsPort()
    {
        AdapterDnsInterceptor interceptor = new();
        string[] domains = [];

        Func<Task> act = () => interceptor.ActivateAsync(IPAddress.Loopback, 5353, domains);

        await act.Should().ThrowAsync<NotSupportedException>();
        interceptor.Mode.Should().Be(InterceptionMode.AdapterDns);
    }
}
