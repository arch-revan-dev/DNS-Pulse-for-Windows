using DnsPulse.Platform.Windows.Networking;
using FluentAssertions;

namespace DnsPulse.Platform.Tests.Networking;

public sealed class NetworkResilienceWatcherTests
{
    [Fact]
    public async Task TriggerChange_DebouncesBurstNotificationsIntoSingleInvocation()
    {
        int invocationCount = 0;
        TaskCompletionSource firstCallback = new(TaskCreationOptions.RunContinuationsAsynchronously);

        using NetworkResilienceWatcher watcher = new(
            _ =>
            {
                int current = Interlocked.Increment(ref invocationCount);
                if (current == 1)
                {
                    firstCallback.TrySetResult();
                }

                return Task.CompletedTask;
            },
            debounceDelay: TimeSpan.FromMilliseconds(80));

        watcher.Start();

        for (int i = 0; i < 5; i++)
        {
            watcher.TriggerChange();
            await Task.Delay(10);
        }

        Task completed = await Task.WhenAny(firstCallback.Task, Task.Delay(TimeSpan.FromSeconds(3)));
        completed.Should().Be(firstCallback.Task);

        await Task.Delay(120);
        Volatile.Read(ref invocationCount).Should().Be(1);
    }

    [Fact]
    public async Task Dispose_CancelsPendingDebouncedCallback_AndPreventsRestart()
    {
        int invocationCount = 0;
        using NetworkResilienceWatcher watcher = new(
            _ =>
            {
                Interlocked.Increment(ref invocationCount);
                return Task.CompletedTask;
            },
            debounceDelay: TimeSpan.FromMilliseconds(200));

        watcher.Start();
        watcher.TriggerChange();
        watcher.Dispose();

        await Task.Delay(300);

        Volatile.Read(ref invocationCount).Should().Be(0);
        Action restart = () => watcher.Start();
        restart.Should().Throw<ObjectDisposedException>();
    }
}
