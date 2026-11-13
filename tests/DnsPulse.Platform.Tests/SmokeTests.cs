using DnsPulse.Platform.Windows;
using FluentAssertions;

namespace DnsPulse.Platform.Tests;

public sealed class SmokeTests
{
    [Fact]
    public void PlatformInfo_PropagatesProduct()
    {
        WindowsPlatformInfo.Product.Should().Be("DNS Pulse");
    }
}
