using System.Net;
using DnsPulse.Engine.Sidecar;
using FluentAssertions;

namespace DnsPulse.Engine.Tests.Sidecar;

public sealed class AutoPacServerTests
{
    [Fact]
    public async Task LiveHttpEndpoints_ServePacAndHealth_AndUpdateSplitDomainsDynamically()
    {
        AutoPacServerOptions options = new()
        {
            BindAddress = IPAddress.Loopback,
            Port = 0,
            ProxyHost = "127.0.53.1",
            ProxyPort = 10808
        };

        await using AutoPacServer server = new(options, ["chatgpt.com", "*.openai.com"]);
        await server.StartAsync();

        server.BoundEndPoint.Should().NotBeNull();
        server.PacUrl.Should().StartWith("http://127.0.0.1:");
        server.PacUrl.Should().EndWith("/proxy.pac");

        using HttpClient httpClient = new();
        string baseUrl = $"http://127.0.0.1:{server.BoundEndPoint!.Port}";

        using HttpResponseMessage pacResponse = await httpClient.GetAsync(new Uri($"{baseUrl}/proxy.pac"));
        pacResponse.StatusCode.Should().Be(HttpStatusCode.OK);
        pacResponse.Content.Headers.ContentType?.MediaType.Should().Be("application/x-ns-proxy-autoconfig");

        string pacScript = await pacResponse.Content.ReadAsStringAsync();
        pacScript.Should().Contain("function FindProxyForURL(url, host)");
        pacScript.Should().Contain("PROXY 127.0.53.1:10808; SOCKS5 127.0.53.1:10808; DIRECT");
        pacScript.Should().Contain("\"chatgpt.com\": 1");
        pacScript.Should().Contain("\"openai.com\": 1");
        pacScript.Should().Contain("return \"DIRECT\";");

        using HttpResponseMessage healthResponse = await httpClient.GetAsync(new Uri($"{baseUrl}/health"));
        healthResponse.StatusCode.Should().Be(HttpStatusCode.OK);
        healthResponse.Content.Headers.ContentType?.MediaType.Should().Be("application/json");
        string healthJson = await healthResponse.Content.ReadAsStringAsync();
        healthJson.Should().Be("{\"status\":\"ok\",\"splitDomainCount\":2}");

        // Dynamically update split domains & proxy port
        server.UpdateProxyEndpoint("192.168.1.50", 20808);
        server.UpdateSplitDomains(["claude.ai", "CLAUDE.AI", "gemini.google.com", "invalid;alert(1)"]);

        string updatedPac = await httpClient.GetStringAsync(new Uri($"{baseUrl}/proxy.pac"));
        updatedPac.Should().Contain("PROXY 192.168.1.50:20808; SOCKS5 192.168.1.50:20808; DIRECT");
        updatedPac.Should().Contain("\"claude.ai\": 1");
        updatedPac.Should().Contain("\"gemini.google.com\": 1");
        updatedPac.Should().NotContain("\"chatgpt.com\"");
        updatedPac.Should().NotContain("alert(1)");

        string updatedHealth = await httpClient.GetStringAsync(new Uri($"{baseUrl}/health"));
        updatedHealth.Should().Be("{\"status\":\"ok\",\"splitDomainCount\":2}");

        using HttpResponseMessage notFound = await httpClient.GetAsync(new Uri($"{baseUrl}/unknown"));
        notFound.StatusCode.Should().Be(HttpStatusCode.NotFound);
    }

    [Fact]
    public void EmptySplitDomains_GeneratesDirectOnlyPacScript()
    {
        AutoPacServerOptions options = new()
        {
            BindAddress = IPAddress.Loopback,
            Port = 0,
            ProxyHost = "127.0.53.1",
            ProxyPort = 10808
        };

        using AutoPacServer server = new(options);
        string script = server.CurrentPacScript;

        script.Should().Contain("function FindProxyForURL(url, host)");
        script.Should().Contain("return \"DIRECT\";");
        script.Should().NotContain("PROXY 127.0.53.1:10808");
    }
}
