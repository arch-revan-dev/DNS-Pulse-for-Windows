# Threat Model

This document defines the security boundaries, threats mitigated by **DNS Pulse v2.0 (PulseCore)**, and residual threats that inherently require a full-tunnel VPN or Tor.

---

## 1. Threat Matrix Summary

| Threat | Mitigated by DNS Pulse? | Mechanism / Caveat |
|---|---|---|
| **ISP Plaintext DNS Hijacking / Poisoning** | ✅ Yes | Routes Zone 4 & security-pinned queries over encrypted `DoH` / `DoH3` / `DoT` / `DoQ` / `DNSCrypt` / `ODoH`; rejects bogon/sinkhole answers via `IpSafetyInspector` & `DnsRebindingValidator`. |
| **Encrypted DNS SNI Blocking (DoH/DoT DPI)** | ✅ Yes | `EncryptedBootstrapResolver` races Direct-IP DoH/DoT, TLS-fragmented DoH (`TlsFragmentingStream`), and falls back safely; supports `DoQ` (QUIC) and `ODoH`. |
| **TLS SNI DPI Resets (`RST` on Port 443)** | ✅ Yes | Driverless `TlsFragmentationProxyServer` + `AutoPacServer` splits the TLS `ClientHello` across the SNI boundary for selected domains. |
| **Regional Geo-Blocks (Smart-DNS Eligible Services)** | ✅ Yes (Scoped) | Zone 3 routes only configured geo-unlock domains to verified Smart-DNS / SNI-Proxy nodes (`AntiDirectAndGeoSignatures` verifies real unlock vs direct CDN IP). |
| **DNS Rebinding Attacks** | ✅ Yes | `DnsRebindingValidator` rejects private, loopback, link-local, CGNAT, ULA, multicast, and IPv4-mapped IPv6 responses for public domains (with explicit opt-in exception solely for named carrier anycast endpoints). |
| **Malicious / Rogue MITM Certificates** | ✅ Yes | Fail-closed `SslStream` OS trust chain + SAN verification (`DiagnosticVerdict.TlsMitmRejected`) + optional `SpkiPinSha256` pinning + Ed25519 signature verification on feeds & release manifests. |
| **Stale Port 53 Conflicts & Broken DNS After Crash** | ✅ Yes | `Port53ConflictInspector` + `LoopbackPortSelector` (`127.0.53.1..10`) + checksummed `NetworkSnapshotJournal` + 10s Dead-Man's Switch + `--restore-network`. |
| **SSRF via PAC Proxy or Community Feeds** | ✅ Yes | `TlsFragmentationProxyServer` (`BlockPrivateDestinationIps`) and `SignedFeedSyncService` (`IpSafetyInspector.IsPublicRoutable`) block requests to loopback/LAN/link-local targets. |
| **Local Privilege Escalation via IPC** | ✅ Yes | Named Pipe `DnsPulse.Control.v1` restricts `FullControl` DACL to `SYSTEM`, `Administrators`, and the interactive user SID, enforces 1 MiB frames, and checks `PipeCommandNames` allowlist. |
| **IP-Level Tracking by Origin Websites** | ❌ No | Origin websites still see your real public IP when connecting directly (or the SNI-Proxy IP only for Zone 3 SNI-Proxy domains, which is **not** an anonymity network). |
| **Volumetric ISP Traffic Shaping / IP-Range Blackholing** | ❌ No | If an ISP null-routes an entire destination IP/ASN (`DiagnosticVerdict.IpBlockedByIsp`) or throttles TCP flows by IP, DNS/TLS-SNI techniques cannot bypass IP-layer routing. Use a full VPN. |
| **Non-DNS / Arbitrary UDP Protocol Censorship** | ❌ No | Game/VoIP UDP streams outside DNS/HTTP/TLS are untouched by DNS Pulse. |

---

## 2. Trust Tiers & Zero-Trust Zone 4 Invariant

DNS Pulse separates resolvers into four trust tiers (`TrustTier`):

1. **`Tier1EncryptedTrusted`** — Audited encrypted resolvers (`DoH`, `DoH3`, `DoT`, `DoQ`, `DnsCrypt`, `AnonymizedDnsCrypt`, `ODoH`). Eligible for **Zone 4** (default internet) and **Security-Pinned** domains (`ocsp.*`, `crl.*`, banking, OS updates, CAs, auth).
2. **`Tier2VerifiedGeoUnlock`** — Verified Smart-DNS / SNI-Proxy nodes. Restricted strictly to **Zone 3** scoped domains; **never** allowed to serve default internet or security-pinned domains.
3. **`Tier3CustomOrSelfHosted`** — User-configured or `SelfHostedVpsGenerator` private nodes (bearer-authenticated + IP-allowlisted).
4. **`Tier4ExperimentalLab`** — Unaudited `/24` scanner discoveries or plaintext lab entries. Strictly blocked from Zone 4 default internet by `TrustTierPolicy.CanServeDefaultInternet`.

---

## 3. Kernel Anti-Cheat Compatibility Caveats

Kernel-level anti-cheat drivers aggressively inspect or block third-party NDIS/WFP callout drivers and raw packet-diversion hooks (`WinDivert`).

- **Default Driverless Mode:** DNS Pulse's default interception modes (`AdapterDns`, `SplitNrpt`, `LocalProxyPacOnly`) and the TLS-Split PAC Sidecar operate **100% in user mode** with zero kernel drivers.
- **Optional `WfpDivertPlugin` Guard (`AntiCheatGuard`):** Before activating `WfpDivertInterceptor`, PulseCore enumerates active processes and refuses/pauses kernel packet diversion if any known anti-cheat process is running:
  - Riot Vanguard (`vgtray`, `vgc`)
  - Easy Anti-Cheat (`EasyAntiCheat`, `EasyAntiCheat_EOS`)
  - FACEIT Anti-Cheat (`FACEITClient`, `faceitservice`)
  - BattlEye (`BEService`)

---

## 4. Supply-Chain & Update Security

- **Release Verification (`VerifiedAppUpdateService`):** Downloads are verified against `SHA256SUMS.txt` (`CryptographicOperations.FixedTimeEquals`), optional detached **Ed25519** signatures (`Ed25519Verifier` enforcing RFC 8032 canonical point/scalar checks and small-order key rejection), and optional Windows Authenticode certificates.
- **Feed Signing (`SignedFeedSyncService`):** Supports `FeedVerificationMode.RequireSigned` to enforce Ed25519 + SHA-256 verification on external domain lists and server feeds, and sanitizes all parsed host/server inputs before storage.
- **Self-Hosted VPS Hardening (`SelfHostedVpsGenerator`):** Refuses to generate open resolvers (`0.0.0.0/0`, `::/0`, `*`, or empty CIDR allowlists are rejected with `ArgumentException`) and mandates a 256-bit cryptographic Bearer token plus UFW firewall rules.
