# Privacy Policy & Telemetry Architecture

**DNS Pulse v2.0 (PulseCore)** is engineered on a strict **zero-telemetry, local-first** privacy model.

---

## 1. Zero Telemetry Guarantee

- **No Analytics SDKs:** DNS Pulse contains **no** third-party telemetry, crash-reporting, advertising, or behavioral analytics SDKs.
- **No Background Beacons:** The application never phones home with usage statistics, active server selections, installed software, or hardware identifiers.
- **Explicit Network Requests Only:** Outbound requests occur solely for:
  1. Your configured DNS queries and bootstrap resolution (`EncryptedBootstrapResolver`).
  2. Explicit diagnostic probes initiated by you (`SixLayerDiagnosticEngine` / `BenchmarkRunner`).
  3. Optional user-triggered feed synchronization (`SignedFeedSyncService`) or GitHub release checks (`VerifiedAppUpdateService`).

---

## 2. In-Memory-Only Telemetry Ring Buffer

Live query metrics displayed in the UI (queries per minute, P50 latency, zone distribution, recent verdicts) are stored exclusively in **`QueryTelemetryBuffer`**:

- Bounded **in-memory** circular buffer (default capacity: **2,000** `DnsQueryTelemetryEvent` items).
- Oldest entries are overwritten automatically in RAM.
- All entries are discarded immediately when the service or process exits.

---

## 3. Zero DNS Query Disk Logging by Default

- **`PulseAppSettings.ZeroDiskQueryLogging` defaults to `true`.**
- DNS query domains (`QName`), client queries, and DNS responses are **never written to disk** in normal operation.
- Operational lifecycle logs written by Serilog to `%LOCALAPPDATA%\DnsPulse\logs\dnspulse-*.log` (7-day rolling retention) record only service startup, shutdown, recovery events, and error diagnostics—never user browsing or DNS query history.

---

## 4. Redacted Diagnostic Bundle Scrubbing

When exporting a support archive via `DiagnosticBundleExporter.ExportRedactedBundleAsync`:

1. **Credentials & Tokens Scrubbed:** Any GitHub tokens, `Authorization: Bearer ...` headers, and sensitive authentication fields in `settings.json` and log files are replaced with `[REDACTED]`.
2. **User Paths Anonymized:** Windows user profile directory prefixes (`%USERPROFILE%`) in log files are scrubbed before archiving.
3. **Query Telemetry Zeroed by Default:** `telemetry.json` inside the exported ZIP contains `events: []` unless the user **explicitly opts in** to include recent in-memory events for debugging.
4. **Atomic Export:** The archive is written via a temporary write-through stream and atomically moved to the chosen destination path.

---

## 5. Local Storage Footprint

All persistent state stays strictly on your machine:

| Path | Purpose | Contains Query History? |
|---|---|---|
| `%APPDATA%\DnsPulse\settings.json` | User preferences & UI settings | No |
| `%LOCALAPPDATA%\DnsPulse\logs\` | Operational lifecycle logs (7-day rolling) | No |
| `%ProgramData%\DnsPulse\` (or `%LOCALAPPDATA%\DnsPulse\`) | Crash-safe `PrePulseNetworkSnapshot` journal for rollback | No |
| Local SQLite catalog DB | Built-in server catalog & probe RTT cache | No |
