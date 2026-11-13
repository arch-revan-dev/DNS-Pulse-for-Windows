using DnsPulse.Platform.Windows.Interception;
using FluentAssertions;

namespace DnsPulse.Platform.Tests.Networking;

public sealed class AntiCheatGuardTests
{
    [Fact]
    public void EvaluateProcessNames_DetectsAllKnownAntiCheatProcesses_CaseInsensitively()
    {
        string[] runningProcesses =
        [
            "explorer",
            "VGTRAY.EXE",
            "vgc",
            "easyanticheat.exe",
            "EasyAntiCheat_EOS",
            "faceitclient",
            "FACEITSERVICE.exe",
            "beservice"
        ];

        (bool isActive, IReadOnlyList<string> detected) = AntiCheatGuard.EvaluateProcessNames(runningProcesses);

        isActive.Should().BeTrue();
        detected.Should().BeEquivalentTo(AntiCheatGuard.MonitoredProcessNames);
    }

    [Fact]
    public void EvaluateProcessNames_DeduplicatesRepeatedMatches()
    {
        string[] runningProcesses = ["vgc", "VGC.exe", "vgtray"];

        (bool isActive, IReadOnlyList<string> detected) = AntiCheatGuard.EvaluateProcessNames(runningProcesses);

        isActive.Should().BeTrue();
        detected.Should().Equal("vgc", "vgtray");
    }

    [Fact]
    public void EvaluateProcessNames_ReturnsFalse_WhenNoAntiCheatIsRunning()
    {
        string[] runningProcesses = ["svchost", "explorer", "dotnet", "DnsPulse.Service"];

        (bool isActive, IReadOnlyList<string> detected) = AntiCheatGuard.EvaluateProcessNames(runningProcesses);

        isActive.Should().BeFalse();
        detected.Should().BeEmpty();
    }

    [Fact]
    public void DetectActiveAntiCheat_ReturnsValidTuple()
    {
        (bool isActive, IReadOnlyList<string> detected) = AntiCheatGuard.DetectActiveAntiCheat();

        detected.Should().NotBeNull();
        isActive.Should().Be(detected.Count > 0);
    }
}
