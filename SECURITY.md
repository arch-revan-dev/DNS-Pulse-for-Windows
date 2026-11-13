# Security Policy

## Supported Versions

Security fixes and integrity patches are actively maintained for the current major release branch:

| Version | Status |
| --- | --- |
| `2.0.x` (PulseCore) | Supported |
| `1.5.x` (Legacy WPF) | Security fixes only (upgrade to `2.0.x` recommended) |
| `< 1.5.0` | End of life (unsupported) |

---

## PulseCore Security Boundaries & Invariants

DNS Pulse v2.0 (**PulseCore**) enforces defense-in-depth across network parsing, IPC privilege separation, cryptography, and Windows state recovery:

1. **Privilege Separation & Named Pipe ACLs (`DnsPulse.App` ↔ `DnsPulse.Service`):**
   - The desktop UI (`DnsPulse.App`) runs strictly unprivileged (`requestedExecutionLevel level="asInvoker"`).
   - Privileged DNS/NRPT/firewall changes are isolated inside `DnsPulseService` (`DnsPulse.Service.exe`) behind `\\.\pipe\DnsPulse.Control.v1`.
   - `PipeSecurityBuilder` strips inherited permissions and grants `FullControl` **only** to `LocalSystemSid`, `BuiltinAdministratorsSid`, and the specific interactive user SID—explicitly rejecting `WorldSid` (Everyone), `AnonymousSid`, and `BuiltinGuestsSid`.
   - `PulsePipeIpcServer` enforces 4-byte little-endian length-prefixed framing capped at **1 MiB** and validates every command against the canonical `PipeCommandNames` allowlist.

2. **Zero-Trust Zone 4 Invariant:**
   - `TrustTierPolicy.CanServeDefaultInternet` strictly blocks `Tier4ExperimentalLab` servers, plaintext `UDP`/`TCP` resolvers, and `SniProxy` nodes from serving Zone 4 default internet traffic or security-pinned domains (`ocsp.*`, `crl.*`, OS updates, banking, CAs, authentication).

3. **Fail-Closed TLS Verification & Pinning:**
   - `DotDnsClient`, `DohDnsClient`, `DoqDnsClient`, and `SixLayerDiagnosticEngine` validate OS-trusted X.509 certificate chains and Subject Alternative Names (SANs) with `TargetHost` enforcement (`TlsMitmRejected` on mismatch/untrusted chain), plus optional `SpkiPinSha256` pinning.

4. **Ed25519 Manifest, Update, and Feed Signing:**
   - `Ed25519Verifier` implements RFC 8032 signature verification with canonical point (`y < p`, curve check, small-order key rejection) and canonical scalar (`s < L`) checks.
   - `VerifiedAppUpdateService` verifies `SHA-256` (`CryptographicOperations.FixedTimeEquals`) against `SHA256SUMS.txt` plus optional detached Ed25519 signatures and Authenticode before staging updates.
   - `SignedFeedSyncService` supports `FeedVerificationMode.RequireSigned` for external feeds and enforces `IpSafetyInspector.IsPublicRoutable` SSRF guards.

5. **DNS Rebinding & SSRF Protections:**
   - `IpSafetyInspector` (including IPv4-mapped IPv6 unwrapping) and `DnsRebindingValidator` reject loopback, RFC 1918, ULA, CGNAT, link-local, and multicast answers for public domains.
   - `TlsFragmentationProxyServer` enforces `BlockPrivateDestinationIps` to prevent SSRF via PAC/HTTP/SOCKS5 proxy requests.

6. **Crash-Safe Recovery & Dead-Man's Switch:**
   - `NetworkSnapshotJournal` persists checksummed pre-Pulse adapter/NRPT/SMHNR state atomically before any network mutation.
   - `DnsPulseWorkerService` polls listener health every 2 seconds and executes `EmergencyRestoreAsync` automatically after 10 seconds of continuous failure, or on `DnsPulse.exe --restore-network` / uninstaller rollback.

7. **Zero Telemetry & Redacted Diagnostics:**
   - Zero DNS query disk logging by default (`ZeroDiskQueryLogging = true`).
   - `DiagnosticBundleExporter` scrubs Bearer/GitHub tokens, `Authorization` headers, and user profile paths, and omits query telemetry unless explicitly opted in.

---

## Reporting a Vulnerability

If you discover a security vulnerability (such as a Named Pipe ACL bypass, Ed25519/SHA-256 verification bypass, DNS rebinding/SSRF bypass, or privilege escalation):

1. **Please do not open a public GitHub Issue** with exploit details.
2. Report privately via **GitHub Security → Advisories → Report a vulnerability** or email `arch.revan.dev@gmail.com` with subject `[SECURITY] DNS Pulse`.
3. Include:
   - Application version and Windows build (`winver`)
   - Reproduction steps or Proof-of-Concept
   - Impact assessment and suggested remediation (if known)

Initial acknowledgment is provided within **72 hours**.
