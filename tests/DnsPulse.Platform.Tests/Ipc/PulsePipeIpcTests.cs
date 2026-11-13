using System.Buffers.Binary;
using System.Globalization;
using System.IO.Pipes;
using System.Text.Json;
using DnsPulse.Platform.Windows.Contracts;
using DnsPulse.Platform.Windows.Ipc;
using FluentAssertions;

namespace DnsPulse.Platform.Tests.Ipc;

public sealed class PulsePipeIpcTests
{
    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        PropertyNameCaseInsensitive = true
    };

    [Fact]
    public async Task ServerAndClient_RoundtripLifecycleCommands_Succeed()
    {
        string pipeName = CreateUniquePipeName();
        bool isConnected = false;

        await using PulsePipeIpcServer server = new(
            (request, _) =>
            {
                switch (request.Command)
                {
                    case PipeCommandNames.GetStatus:
                        ServiceStatusSnapshot currentStatus = new()
                        {
                            IsConnected = isConnected,
                            IsHealthy = isConnected,
                            ActiveMode = isConnected ? InterceptionMode.AdapterDns : InterceptionMode.None,
                            BoundDnsPort = isConnected ? 53 : 0
                        };
                        return Task.FromResult(new PipeRpcResponse(
                            request.RequestId,
                            true,
                            PayloadJson: JsonSerializer.Serialize(currentStatus, JsonOptions)));

                    case PipeCommandNames.Connect:
                        isConnected = true;
                        ServiceStatusSnapshot connectedStatus = new()
                        {
                            IsConnected = true,
                            IsHealthy = true,
                            ActiveMode = InterceptionMode.AdapterDns,
                            BoundDnsPort = 53
                        };
                        return Task.FromResult(new PipeRpcResponse(
                            request.RequestId,
                            true,
                            PayloadJson: JsonSerializer.Serialize(connectedStatus, JsonOptions)));

                    case PipeCommandNames.Disconnect:
                        isConnected = false;
                        ServiceStatusSnapshot disconnectedStatus = new()
                        {
                            IsConnected = false,
                            IsHealthy = false,
                            ActiveMode = InterceptionMode.None
                        };
                        return Task.FromResult(new PipeRpcResponse(
                            request.RequestId,
                            true,
                            PayloadJson: JsonSerializer.Serialize(disconnectedStatus, JsonOptions)));

                    case PipeCommandNames.EmergencyRestore:
                        isConnected = false;
                        NetworkRestoredResult restored = new(
                            HadDirtyState: true,
                            AdaptersRestored: 2,
                            PoliciesCleaned: true,
                            Summary: "Restored 2 adapters.");
                        return Task.FromResult(new PipeRpcResponse(
                            request.RequestId,
                            true,
                            PayloadJson: JsonSerializer.Serialize(restored, JsonOptions)));

                    default:
                        return Task.FromResult(new PipeRpcResponse(request.RequestId, false, "Unexpected"));
                }
            },
            pipeName);

        await server.StartAsync();

        PulsePipeIpcClient client = new(pipeName, TimeSpan.FromSeconds(5));

        PipeRpcResponse initialStatus = await client.SendAsync(new PipeRpcRequest("req-1", PipeCommandNames.GetStatus));
        initialStatus.Success.Should().BeTrue();
        JsonSerializer.Deserialize<ServiceStatusSnapshot>(initialStatus.PayloadJson!, JsonOptions)!.IsConnected.Should().BeFalse();

        PipeRpcResponse connectResp = await client.SendAsync(new PipeRpcRequest("req-2", PipeCommandNames.Connect));
        connectResp.Success.Should().BeTrue();
        JsonSerializer.Deserialize<ServiceStatusSnapshot>(connectResp.PayloadJson!, JsonOptions)!.IsConnected.Should().BeTrue();

        PipeRpcResponse disconnectResp = await client.SendAsync(new PipeRpcRequest("req-3", PipeCommandNames.Disconnect));
        disconnectResp.Success.Should().BeTrue();
        JsonSerializer.Deserialize<ServiceStatusSnapshot>(disconnectResp.PayloadJson!, JsonOptions)!.IsConnected.Should().BeFalse();

        PipeRpcResponse restoreResp = await client.SendAsync(new PipeRpcRequest("req-4", PipeCommandNames.EmergencyRestore));
        restoreResp.Success.Should().BeTrue();
        NetworkRestoredResult? restoredResult = JsonSerializer.Deserialize<NetworkRestoredResult>(restoreResp.PayloadJson!, JsonOptions);
        restoredResult.Should().NotBeNull();
        restoredResult!.AdaptersRestored.Should().Be(2);
        restoredResult.PoliciesCleaned.Should().BeTrue();

        await server.StopAsync();
    }

    [Fact]
    public async Task Server_RejectsDisallowedCommand_WithoutInvokingHandler()
    {
        string pipeName = CreateUniquePipeName();
        bool handlerInvoked = false;

        await using PulsePipeIpcServer server = new(
            (request, _) =>
            {
                handlerInvoked = true;
                return Task.FromResult(new PipeRpcResponse(request.RequestId, true));
            },
            pipeName);

        await server.StartAsync();
        PulsePipeIpcClient client = new(pipeName);

        PipeRpcResponse response = await client.SendAsync(new PipeRpcRequest("req-bad", "ExecuteArbitraryShell"));

        handlerInvoked.Should().BeFalse();
        response.RequestId.Should().Be("req-bad");
        response.Success.Should().BeFalse();
        response.ErrorCode.Should().Be("UnknownCommand");
    }

    [Fact]
    public async Task ClientAndServer_RejectOversizedFramesExceedingOneMiB()
    {
        string pipeName = CreateUniquePipeName();
        bool handlerInvoked = false;

        await using PulsePipeIpcServer server = new(
            (request, _) =>
            {
                handlerInvoked = true;
                return Task.FromResult(new PipeRpcResponse(request.RequestId, true));
            },
            pipeName);

        await server.StartAsync();
        PulsePipeIpcClient client = new(pipeName);

        // 1. Client-side guard rejects > 1 MiB payloads before writing.
        string oversizedPayload = new('A', PulsePipeIpcServer.DefaultMaxMessageBytes + 128);
        Func<Task> oversizedClientCall = () => client.SendAsync(
            new PipeRpcRequest("req-big", PipeCommandNames.ApplyProfile, oversizedPayload));
        await oversizedClientCall.Should().ThrowAsync<InvalidDataException>();

        // 2. Server-side framing guard rejects raw > 1 MiB length header without allocating payload buffer.
        await using (NamedPipeClientStream rawClient = new(".", pipeName, PipeDirection.InOut, PipeOptions.Asynchronous))
        {
            await rawClient.ConnectAsync(3000);
            byte[] badHeader = new byte[4];
            BinaryPrimitives.WriteInt32LittleEndian(badHeader, PulsePipeIpcServer.DefaultMaxMessageBytes + 1);
            await rawClient.WriteAsync(badHeader);
            await rawClient.FlushAsync();

            byte[] responseLenBytes = new byte[4];
            int headerBytesRead = 0;
            while (headerBytesRead < responseLenBytes.Length)
            {
                int read = await rawClient.ReadAsync(responseLenBytes.AsMemory(headerBytesRead));
                read.Should().BeGreaterThan(0);
                headerBytesRead += read;
            }
            int responseLength = BinaryPrimitives.ReadInt32LittleEndian(responseLenBytes);
            responseLength.Should().BeGreaterThan(0).And.BeLessThanOrEqualTo(PulsePipeIpcServer.DefaultMaxMessageBytes);

            byte[] responseBody = new byte[responseLength];
            int totalBodyRead = 0;
            while (totalBodyRead < responseLength)
            {
                int read = await rawClient.ReadAsync(responseBody.AsMemory(totalBodyRead));
                read.Should().BeGreaterThan(0);
                totalBodyRead += read;
            }

            PipeRpcResponse? errorResponse = JsonSerializer.Deserialize<PipeRpcResponse>(responseBody, JsonOptions);
            errorResponse.Should().NotBeNull();
            errorResponse!.Success.Should().BeFalse();
            errorResponse.ErrorCode.Should().Be("FrameTooLarge");
        }

        handlerInvoked.Should().BeFalse();

        // 3. Server remains healthy for subsequent valid requests.
        PipeRpcResponse healthyResponse = await client.SendAsync(new PipeRpcRequest("req-ok", PipeCommandNames.GetStatus));
        healthyResponse.Success.Should().BeTrue();
        handlerInvoked.Should().BeTrue();
    }

    [Fact]
    public async Task Client_ThrowsTimeoutException_WhenPipeDoesNotExistWithinTimeout()
    {
        string missingPipe = CreateUniquePipeName();
        PulsePipeIpcClient client = new(missingPipe, TimeSpan.FromMilliseconds(150));

        Func<Task> call = () => client.SendAsync(new PipeRpcRequest("req-timeout", PipeCommandNames.GetStatus));
        await call.Should().ThrowAsync<TimeoutException>();
    }

    private static string CreateUniquePipeName()
    {
        return string.Create(CultureInfo.InvariantCulture, $"DnsPulse.Test.{Guid.NewGuid():N}");
    }
}
