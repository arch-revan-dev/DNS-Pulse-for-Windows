<div align="center">

<img src="src/DnsPulse.App/Assets/app.ico" alt="DNS Pulse Icon" width="76" height="76" />

# DNS Pulse v2.0 (PulseCore) for Windows

**Open-source encrypted DNS router, 4-zone split-namespace engine, 6-layer availability doctor, and driverless TLS-split PAC sidecar for Windows 10/11.**

**[Русская версия (README.ru.md)](README.ru.md)**

[![Release](https://img.shields.io/github/v/release/arch-revan-dev/DNS-Pulse-for-Windows?style=for-the-badge&logo=github&color=10b981)](https://github.com/arch-revan-dev/DNS-Pulse-for-Windows/releases/latest)
[![CI](https://img.shields.io/github/actions/workflow/status/arch-revan-dev/DNS-Pulse-for-Windows/ci.yml?branch=main&style=for-the-badge&logo=githubactions&label=CI)](https://github.com/arch-revan-dev/DNS-Pulse-for-Windows/actions/workflows/ci.yml)
[![Security](https://img.shields.io/github/actions/workflow/status/arch-revan-dev/DNS-Pulse-for-Windows/security.yml?branch=main&style=for-the-badge&logo=githubactions&label=Security)](https://github.com/arch-revan-dev/DNS-Pulse-for-Windows/actions/workflows/security.yml)
[![Platform](https://img.shields.io/badge/Windows-10%20%2F%2011%20(x64%20%7C%20arm64)-0078D6?style=for-the-badge&logo=windows11)](https://github.com/arch-revan-dev/DNS-Pulse-for-Windows/releases)
[![.NET](https://img.shields.io/badge/.NET-9.0%20PulseCore-512BD4?style=for-the-badge&logo=dotnet)](https://dotnet.microsoft.com/)
[![License](https://img.shields.io/github/license/arch-revan-dev/DNS-Pulse-for-Windows?style=for-the-badge&color=64748b)](LICENSE)

[Features](#-pulsecore-v20-feature-matrix) • [Quickstart](#-quickstart) • [Architecture](#-architecture-overview) • [6-Layer Doctor](docs/DNS_DIAGNOSTICS.md) • [Threat Model](docs/THREAT_MODEL.md) • [Privacy](docs/PRIVACY.md) • [Self-Hosted VPS](docs/SELF_HOSTED_VPS.md) • [Security](SECURITY.md)

</div>

---

## Why DNS Pulse?

Standard DNS benchmarks only measure ICMP ping to `1.1.1.1` or `8.8.8.8`. That tells you nothing about whether your ISP is hijacking plaintext DNS, injecting TCP resets during TLS SNI inspection, blocking encrypted DNS endpoints, or whether a Smart-DNS node returns a direct CDN IP that immediately triggers a regional `403`/`451` geo-block.

**DNS Pulse v2.0 (PulseCore)** replaces ad-hoc scripts with a deterministic, zero-telemetry `.NET 9` DNS router featuring a **4-Zone Split-Namespace Engine**, **6-Layer Availability Doctor**, **Driverless TLS-Split PAC Sidecar** (anti-cheat safe), **Ed25519-verified feeds/updates**, and a **Dead-Man's Switch** that guarantees your Windows network configuration is never left broken.

---

## PulseCore v2.0 Feature Matrix

| Capability | PulseCore v2.0 Implementation |
|---|---|
| **Encrypted DNS Transports** | `DoH` (HTTP/2 POST/GET), `DoH3` (HTTP/3), `DoT` (RFC 7858), `DoQ` (RFC 9250 QUIC), `DNSCrypt v2`, `Anonymized DNSCrypt`, `ODoH` (RFC 9230 HPKE), `DDR` (`_dns.resolver.arpa`), `sdns://` Stamps |
| **4-Zone Split-Namespace** | Lock-free radix tries (`DomainRadixTrie`, `CidrRadixTrie`) with strict precedence: `Zone 1 Local` > `Security Pinning` > `Zone 2 Block/Allow` > `Zone 3 Geo-Unlock` > `Zone 4 Encrypted Trusted` |
| **ECH & HTTPS/SVCB** | Preserves `HTTPS (65)`/`SVCB (64)` `ECH` keys in Zone 4 for privacy; cleanly strips ECH/IPv6 hints in Zone 3 (`HttpsSvcbRouteRewriter`) for Smart-DNS/SNI-Proxy IPv4 compatibility |
| **6-Layer Availability Doctor** | Host health (Port 53 / Browser DoH) → Multi-sample RTT (`p50`/`p95`/jitter) → Baseline integrity → Fail-closed X.509/SAN/ALPN → HTTPS Geo-probe + Companion APIs → Actionable verdict |
| **Driverless TLS-Split Sidecar** | `AutoPacServer` (`/proxy.pac`) + `TlsFragmentationProxyServer` (HTTP `CONNECT`, HTTP, SOCKS5) splitting TLS `ClientHello` across SNI boundaries with SSRF protection — zero kernel drivers |
| **Crash-Safe Recovery** | Atomic checksummed `NetworkSnapshotJournal`, 10-second `DnsPulseService` Dead-Man's Switch watchdog, Start Menu **Emergency Network Restore** (`--restore-network`), and uninstaller rollback |
| **Self-Hosted VPS Wizard** | `SelfHostedVpsGenerator` outputs hardened `docker-compose.yml`, IP-allowlisted + Bearer-authenticated `nginx.conf`, `Corefile`/`AdGuardHome.yaml`, UFW script, and `sdns://` stamp |
| **Zero Telemetry** | In-memory-only `QueryTelemetryBuffer` (2,000 events), `ZeroDiskQueryLogging = true` by default, redacted diagnostic ZIP exporter |

---

## Security Guarantees

- **Unprivileged UI + ACL-Hardened Service:** `DnsPulse.App` runs as `asInvoker`. Privileged Win32/NRPT/COM-Firewall operations run inside `DnsPulse.Service.exe` behind `\\.\pipe\DnsPulse.Control.v1` with DACLs restricted exclusively to `SYSTEM`, `Administrators`, and the interactive user SID.
- **Zero-Trust Zone 4 Invariant:** `Tier4ExperimentalLab`, plaintext `UDP`/`TCP`, and `SniProxy` servers are strictly forbidden from Zone 4 default internet and security-pinned domains (`ocsp.*`, `crl.*`, OS updates, banking, CAs, auth).
- **Anti-Cheat Safe by Default:** Interception modes (`AdapterDns`, `SplitNrpt`, `LocalProxyPacOnly`) and the TLS-Split PAC Sidecar run in user mode without kernel drivers. Optional `WfpDivertPlugin` automatically refuses activation when Riot Vanguard, Easy Anti-Cheat, FACEIT, or BattlEye is detected.
- **Cryptographic Verification:** RFC 8032 `Ed25519Verifier` + constant-time `SHA-256` verification for release updates and signed feeds (`RequireSigned`).

---

## Quickstart

1. Download the latest release from **[GitHub Releases](https://github.com/arch-revan-dev/DNS-Pulse-for-Windows/releases/latest)**:
   - **`DNS-Pulse-win-x64-setup.exe`** (or `win-arm64`) — Inno Setup installer with optional Windows Service and Emergency Network Restore shortcut.
   - **`DNS-Pulse-win-x64-portable.zip`** — Self-contained portable archive.
2. *(Optional)* Verify checksums against `SHA256SUMS.txt`:
   ```powershell
   Get-FileHash .\DNS-Pulse-win-x64-setup.exe -Algorithm SHA256
   ```
3. Launch **DNS Pulse**, run the **6-Layer Availability Doctor** or **Auto-Select** to pick a healthy `Tier1EncryptedTrusted` resolver, and connect.
4. To revert all network settings at any time—even if DNS Pulse is closed—run **Start Menu → DNS Pulse → Emergency Network Restore** (`DnsPulse.exe --restore-network`).

---

## Architecture Overview

```text
DNS-Pulse-for-Windows/
├── .github/workflows/           # ci.yml, release.yml, security.yml (CodeQL + Scorecard)
├── assets/dns_catalog_1000.tsv  # Built-in server catalog + flagship resolvers
├── docs/                        # ARCHITECTURE, THREAT_MODEL, PRIVACY, DNS_DIAGNOSTICS, SELF_HOSTED_VPS
├── installer/                   # Inno Setup (DnsPulse.iss), WiX v4 (wix/Package.wxs), WinGet manifests
├── src/
│   ├── DnsPulse.Core/           # Pure net9.0 domain models, wire codec, 4-zone radix router, stamps, Ed25519
│   ├── DnsPulse.Engine/         # Transports, bootstrap, optimistic cache, sidecar, 6-layer doctor, VPS gen
│   ├── DnsPulse.Platform.Windows/ # Win32 NIC/NRPT/COM firewall, snapshot journal, ACL Named Pipe, updater
│   ├── DnsPulse.Service/        # Windows Service host + 10s Dead-Man's Switch watchdog
│   └── DnsPulse.App/            # .NET 9 WPF-UI 4.3.0 desktop application (asInvoker)
├── tests/                       # xUnit + FluentAssertions test suites (Core, Engine, Platform, App)
└── tools/web-studio/            # Optional cross-platform TypeScript/React diagnostic web studio
```

Deep-dive documentation:
- [PulseCore Architecture](docs/ARCHITECTURE.md)
- [Threat Model](docs/THREAT_MODEL.md)
- [Privacy & Telemetry Policy](docs/PRIVACY.md)
- [6-Layer Diagnostics Guide](docs/DNS_DIAGNOSTICS.md)
- [Self-Hosted Hardened VPS Guide](docs/SELF_HOSTED_VPS.md)

---

## Building from Source

### Prerequisites
- [.NET 9 SDK](https://dotnet.microsoft.com/download/dotnet/9.0) on Windows 10/11 (`10.0.19041.0`+)
- Optional: [Inno Setup 6](https://jrsoftware.org/isinfo.php) or [WiX Toolset v4](https://wixtoolset.org/) for packaging installers

### Build & Test (`.NET 9`)
```powershell
dotnet restore DnsPulse.sln
dotnet test DnsPulse.sln --configuration Release --no-restore

# Publish single-file desktop app (win-x64 or win-arm64)
dotnet publish src/DnsPulse.App/DnsPulse.App.csproj `
  -c Release -r win-x64 --self-contained true `
  -p:PublishSingleFile=true -p:IncludeNativeLibrariesForSelfExtract=true `
  -o artifacts/win-x64

# Publish Windows Service alongside the desktop binary
dotnet publish src/DnsPulse.Service/DnsPulse.Service.csproj `
  -c Release -r win-x64 --self-contained true `
  -p:PublishSingleFile=true -o artifacts/win-x64

# Build Inno Setup installer
iscc.exe /DArch=win-x64 /DAppVersion=2.0.0 installer/DnsPulse.iss
```

---

## Contributing & License

Contributions are welcome! Please review [CONTRIBUTING.md](CONTRIBUTING.md) and [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md) before opening a Pull Request.

Licensed under the [MIT License](LICENSE). © 2026 DNS Pulse Open Source Contributors.
