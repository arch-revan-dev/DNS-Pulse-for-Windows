using DnsPulse.Engine.Contracts;

namespace DnsPulse.Engine.Pipeline;

/// <summary>
/// Event arguments carrying a recorded <see cref="DnsQueryTelemetryEvent"/>.
/// </summary>
public sealed class DnsQueryTelemetryEventArgs(DnsQueryTelemetryEvent telemetryEvent) : EventArgs
{
    public DnsQueryTelemetryEvent TelemetryEvent { get; } = telemetryEvent ?? throw new ArgumentNullException(nameof(telemetryEvent));
}

/// <summary>
/// Thread-safe bounded in-memory ring buffer storing recent <see cref="DnsQueryTelemetryEvent"/> entries
/// without persisting query domains or PII to disk.
/// </summary>
public sealed class QueryTelemetryBuffer
{
    public const int DefaultCapacity = 2000;

    private readonly DnsQueryTelemetryEvent[] _buffer;
    private readonly TimeProvider _timeProvider;
    private readonly Lock _gate = new();

    private int _nextIndex;
    private int _count;
    private long _totalRecordedCount;

    public QueryTelemetryBuffer(int capacity = DefaultCapacity, TimeProvider? timeProvider = null)
    {
        ArgumentOutOfRangeException.ThrowIfLessThan(capacity, 1);

        _buffer = new DnsQueryTelemetryEvent[capacity];
        _timeProvider = timeProvider ?? TimeProvider.System;
    }

    /// <summary>
    /// Raised outside internal locks whenever a new telemetry event is recorded.
    /// </summary>
    public event EventHandler<DnsQueryTelemetryEventArgs>? EventRecorded;

    public int Capacity => _buffer.Length;

    public int Count
    {
        get
        {
            lock (_gate)
            {
                return _count;
            }
        }
    }

    public long TotalRecordedCount => Volatile.Read(ref _totalRecordedCount);

    /// <summary>
    /// Computes the number of queries recorded in the trailing 60-second window.
    /// </summary>
    public double QueriesPerMinute
    {
        get
        {
            DateTimeOffset cutoff = _timeProvider.GetUtcNow().AddMinutes(-1);
            int recentCount = 0;

            lock (_gate)
            {
                for (int i = 0; i < _count; i++)
                {
                    int index = GetChronologicalIndexLocked(i);
                    if (_buffer[index].TimestampUtc >= cutoff)
                    {
                        recentCount++;
                    }
                }
            }

            return recentCount;
        }
    }

    /// <summary>
    /// Computes the median (50th percentile) latency in milliseconds across all currently buffered events.
    /// </summary>
    public double P50LatencyMs
    {
        get
        {
            double[] latencies;
            lock (_gate)
            {
                if (_count == 0)
                {
                    return 0.0;
                }

                latencies = new double[_count];
                for (int i = 0; i < _count; i++)
                {
                    latencies[i] = _buffer[GetChronologicalIndexLocked(i)].LatencyMs;
                }
            }

            Array.Sort(latencies);
            int mid = latencies.Length / 2;
            if ((latencies.Length & 1) == 1)
            {
                return latencies[mid];
            }

            return (latencies[mid - 1] + latencies[mid]) / 2.0;
        }
    }

    /// <summary>
    /// Appends a telemetry event to the bounded ring buffer, overwriting the oldest entry when full.
    /// </summary>
    public void Record(DnsQueryTelemetryEvent telemetryEvent)
    {
        ArgumentNullException.ThrowIfNull(telemetryEvent);

        lock (_gate)
        {
            _buffer[_nextIndex] = telemetryEvent;
            _nextIndex = (_nextIndex + 1) % _buffer.Length;
            if (_count < _buffer.Length)
            {
                _count++;
            }
        }

        Interlocked.Increment(ref _totalRecordedCount);
        EventHandler<DnsQueryTelemetryEventArgs>? handler = EventRecorded;
        handler?.Invoke(this, new DnsQueryTelemetryEventArgs(telemetryEvent));
    }

    /// <summary>
    /// Returns up to <paramref name="maxCount"/> most recent telemetry events ordered newest-first.
    /// </summary>
    public IReadOnlyList<DnsQueryTelemetryEvent> GetRecentEvents(int maxCount = 100)
    {
        ArgumentOutOfRangeException.ThrowIfLessThan(maxCount, 0);

        if (maxCount == 0)
        {
            return [];
        }

        lock (_gate)
        {
            int take = Math.Min(maxCount, _count);
            if (take == 0)
            {
                return [];
            }

            DnsQueryTelemetryEvent[] snapshot = new DnsQueryTelemetryEvent[take];
            for (int i = 0; i < take; i++)
            {
                int offsetFromLatest = i + 1;
                int index = (_nextIndex - offsetFromLatest + _buffer.Length) % _buffer.Length;
                snapshot[i] = _buffer[index];
            }

            return snapshot;
        }
    }

    /// <summary>
    /// Clears all buffered events.
    /// </summary>
    public void Clear()
    {
        lock (_gate)
        {
            Array.Clear(_buffer, 0, _buffer.Length);
            _nextIndex = 0;
            _count = 0;
        }
    }

    private int GetChronologicalIndexLocked(int offsetFromOldest)
    {
        int oldestIndex = _count == _buffer.Length ? _nextIndex : 0;
        return (oldestIndex + offsetFromOldest) % _buffer.Length;
    }
}
