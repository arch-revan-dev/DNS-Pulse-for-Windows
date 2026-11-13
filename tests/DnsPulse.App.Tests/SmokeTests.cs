using DnsPulse.App.ViewModels;
using FluentAssertions;

namespace DnsPulse.App.Tests;

public sealed class SmokeTests
{
    [Fact]
    public void MainViewModel_DefaultTitle_ContainsProductName()
    {
        MainViewModel viewModel = new();
        viewModel.Title.Should().Contain("DNS Pulse");
    }
}
