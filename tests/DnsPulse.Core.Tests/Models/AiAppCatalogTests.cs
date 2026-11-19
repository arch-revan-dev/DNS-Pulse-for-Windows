using DnsPulse.Core.Models;
using FluentAssertions;

namespace DnsPulse.Core.Tests.Models;

public sealed class AiAppCatalogTests
{
    [Fact]
    public void DesktopApps_ShouldIncludeAntigravityClaudeCodeCursorAndWindsurf()
    {
        AiAppCatalog.DesktopApps.Should().Contain(static a => a.Id == "antigravity");
        AiAppCatalog.DesktopApps.Should().Contain(static a => a.Id == "claude_code");
        AiAppCatalog.DesktopApps.Should().Contain(static a => a.Id == "claude_desktop");
        AiAppCatalog.DesktopApps.Should().Contain(static a => a.Id == "cursor");
        AiAppCatalog.DesktopApps.Should().Contain(static a => a.Id == "windsurf");
        AiAppCatalog.DesktopApps.Should().Contain(static a => a.Id == "gemini_cli");
        AiAppCatalog.DesktopApps.Should().Contain(static a => a.Id == "codex_cli");
    }

    [Fact]
    public void LoopbackSafeNoProxy_ShouldAlwaysExcludeLoopbackAddressesToProtectAntigravityIpc()
    {
        AiAppCatalog.LoopbackSafeNoProxy.Should().Contain("localhost");
        AiAppCatalog.LoopbackSafeNoProxy.Should().Contain("127.0.0.1");
        AiAppCatalog.LoopbackSafeNoProxy.Should().Contain("::1");
        AiAppCatalog.ChromiumProxyBypassList.Should().Contain("<-loopback>");
    }

    [Theory]
    [InlineData("antigravity.google", true)]
    [InlineData("cloudcode-pa.googleapis.com", true)]
    [InlineData("mcp-proxy.anthropic.com", true)]
    [InlineData("console.anthropic.com", true)]
    [InlineData("api2.cursor.sh", true)]
    [InlineData("server.codeium.com", true)]
    [InlineData("api.deepseek.com", true)]
    [InlineData("example.com", false)]
    public void ServerCategoryClassifier_IsAiDomain_ShouldRecognizeDesktopAiAppDomains(string domain, bool expected)
    {
        ServerCategoryClassifier.IsAiDomain(domain).Should().Be(expected);
    }

    [Fact]
    public void AllAiAndAppDomains_ShouldBeDeduplicatedSupersetOfBuiltinAiDomains()
    {
        AiAppCatalog.AllAiAndAppDomains.Should().Contain(BuiltInCatalogPresets.BuiltinAiDomains);
        AiAppCatalog.AllAiAndAppDomains.Should().Contain(AiAppCatalog.ExtraDesktopAiDomains);
        AiAppCatalog.AllAiAndAppDomains.Should().OnlyHaveUniqueItems(StringComparer.OrdinalIgnoreCase);
    }
}
