using System.Net.NetworkInformation;
using Microsoft.Win32;

namespace DnsPulse.Platform.Windows.Networking;

/// <summary>
/// Watches Windows network address changes and system power-resume events, invoking a debounced asynchronous callback.
/// </summary>
public sealed class NetworkResilienceWatcher : IDisposable
{
    private readonly Func<CancellationToken, Task> _onNetworkOrPowerChanged;
    private readonly TimeSpan _debounceDelay;
    private readonly Lock _syncLock = new();

    private CancellationTokenSource? _lifetimeCts;
    private CancellationTokenSource? _debounceCts;
    private bool _started;
    private bool _disposed;

    /// <summary>
    /// Initializes a new <see cref="NetworkResilienceWatcher"/>.
    /// </summary>
    public NetworkResilienceWatcher(
        Func<CancellationToken, Task> onNetworkOrPowerChanged,
        TimeSpan? debounceDelay = null)
    {
        ArgumentNullException.ThrowIfNull(onNetworkOrPowerChanged);

        TimeSpan resolvedDelay = debounceDelay ?? TimeSpan.FromMilliseconds(500);
        ArgumentOutOfRangeException.ThrowIfLessThan(resolvedDelay, TimeSpan.Zero);

        _onNetworkOrPowerChanged = onNetworkOrPowerChanged;
        _debounceDelay = resolvedDelay;
    }

    /// <summary>
    /// Starts listening for Windows network address changes and power resume events.
    /// </summary>
    public void Start()
    {
        lock (_syncLock)
        {
            ObjectDisposedException.ThrowIf(_disposed, this);

            if (_started)
            {
                return;
            }

            _lifetimeCts = new CancellationTokenSource();
            _started = true;
        }

        NetworkChange.NetworkAddressChanged += OnNetworkAddressChanged;
        SystemEvents.PowerModeChanged += OnPowerModeChanged;
    }

    /// <summary>
    /// Manually enqueues a debounced change notification when the watcher is active.
    /// </summary>
    public void TriggerChange()
    {
        ScheduleDebouncedCallback();
    }

    /// <summary>
    /// Unhooks system events and cancels any pending debounced callbacks.
    /// </summary>
    public void Dispose()
    {
        CancellationTokenSource? lifetimeCts;
        CancellationTokenSource? debounceCts;
        bool wasStarted;

        lock (_syncLock)
        {
            if (_disposed)
            {
                return;
            }

            _disposed = true;
            wasStarted = _started;
            _started = false;
            lifetimeCts = _lifetimeCts;
            _lifetimeCts = null;
            debounceCts = _debounceCts;
            _debounceCts = null;
        }

        if (wasStarted)
        {
            NetworkChange.NetworkAddressChanged -= OnNetworkAddressChanged;
            SystemEvents.PowerModeChanged -= OnPowerModeChanged;
        }

        CancelSafely(debounceCts);
        debounceCts?.Dispose();
        CancelSafely(lifetimeCts);
        lifetimeCts?.Dispose();
    }

    private void OnNetworkAddressChanged(object? sender, EventArgs e)
    {
        ScheduleDebouncedCallback();
    }

    private void OnPowerModeChanged(object sender, PowerModeChangedEventArgs e)
    {
        if (e.Mode == PowerModes.Resume)
        {
            ScheduleDebouncedCallback();
        }
    }

    private void ScheduleDebouncedCallback()
    {
        CancellationTokenSource? previousDebounce;
        CancellationTokenSource nextDebounce;
        CancellationToken lifetimeToken;

        lock (_syncLock)
        {
            if (_disposed || !_started || _lifetimeCts is null)
            {
                return;
            }

            previousDebounce = _debounceCts;
            nextDebounce = CancellationTokenSource.CreateLinkedTokenSource(_lifetimeCts.Token);
            _debounceCts = nextDebounce;
            lifetimeToken = _lifetimeCts.Token;
        }

        CancelSafely(previousDebounce);
        _ = RunDebouncedAsync(nextDebounce, lifetimeToken);
    }

    private async Task RunDebouncedAsync(CancellationTokenSource debounceCts, CancellationToken lifetimeToken)
    {
        try
        {
            if (_debounceDelay > TimeSpan.Zero)
            {
                await Task.Delay(_debounceDelay, debounceCts.Token);
            }

            if (!debounceCts.IsCancellationRequested && !lifetimeToken.IsCancellationRequested)
            {
                await _onNetworkOrPowerChanged(lifetimeToken);
            }
        }
        catch (OperationCanceledException)
        {
        }
        finally
        {
            lock (_syncLock)
            {
                if (ReferenceEquals(_debounceCts, debounceCts))
                {
                    _debounceCts = null;
                }
            }

            debounceCts.Dispose();
        }
    }

    private static void CancelSafely(CancellationTokenSource? cts)
    {
        if (cts is null)
        {
            return;
        }

        try
        {
            cts.Cancel();
        }
        catch (ObjectDisposedException)
        {
        }
    }
}
