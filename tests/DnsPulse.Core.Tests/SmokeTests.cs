using FluentAssertions;

namespace DnsPulse.Core.Tests;

public sealed class SmokeTests
{
    [Fact]
    public void ProductName_IsConfigured()
    {
        CoreAssemblyInfo.ProductName.Should().Be("DNS Pulse");
    }
}
