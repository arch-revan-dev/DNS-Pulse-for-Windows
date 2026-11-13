using FluentAssertions;

namespace DnsPulse.Engine.Tests;

public sealed class SmokeTests
{
    [Fact]
    public void Product_PropagatesFromCore()
    {
        EngineAssemblyInfo.Product.Should().Be("DNS Pulse");
    }
}
