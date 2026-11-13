using DnsPulse.Core.Models;

namespace DnsPulse.Engine.Bootstrap;

/// <summary>
/// Configuration options for <see cref="EncryptedBootstrapResolver"/>'s Happy Eyeballs encrypted-first race.
/// </summary>
public sealed record BootstrapOptions
{
    /// <summary>Gets the stagger delay between launching parallel bootstrap candidates (default 250 ms).</summary>
    public TimeSpan StaggerDelay { get; init; } = TimeSpan.FromMilliseconds(250);

    /// <summary>Gets the per-query timeout applied to each bootstrap candidate.</summary>
    public TimeSpan CandidateTimeout { get; init; } = TimeSpan.FromSeconds(4);

    /// <summary>Gets whether <see cref="ResolveHostAsync"/> also queries AAAA records alongside A records.</summary>
    public bool QueryIpv6 { get; init; } = true;

    /// <summary>Gets the Tier A direct-IP encrypted DoH and DoT bootstrap endpoints.</summary>
    public IReadOnlyList<DnsServerEntry> DirectEncryptedEndpoints { get; init; } = CreateDefaultDirectEncryptedEndpoints();

    /// <summary>Gets the Tier B TLS-fragmented DoH fallback endpoints.</summary>
    public IReadOnlyList<DnsServerEntry> FragmentedDohEndpoints { get; init; } = CreateDefaultFragmentedDohEndpoints();

    /// <summary>Gets the Tier C last-resort plaintext UDP/TCP 53 endpoints (strictly bogon-filtered).</summary>
    public IReadOnlyList<DnsServerEntry> PlaintextFallbackEndpoints { get; init; } = CreateDefaultPlaintextFallbackEndpoints();

    public static IReadOnlyList<DnsServerEntry> CreateDefaultDirectEncryptedEndpoints()
    {
        return
        [
            new DnsServerEntry
            {
                Id = "bootstrap_cf_doh",
                Name = "Cloudflare Bootstrap DoH",
                Provider = "Cloudflare",
                Protocol = DnsProtocol.DoH,
                TrustTier = TrustTier.Tier1EncryptedTrusted,
                PrimaryIp = "1.1.1.1",
                DohUrl = "https://1.1.1.1/dns-query",
                DotHost = "cloudflare-dns.com",
                BootstrapIps = ["1.1.1.1", "1.0.0.1"],
                Port = 443,
                IsBuiltin = true
            },
            new DnsServerEntry
            {
                Id = "bootstrap_quad9_doh",
                Name = "Quad9 Bootstrap DoH",
                Provider = "Quad9",
                Protocol = DnsProtocol.DoH,
                TrustTier = TrustTier.Tier1EncryptedTrusted,
                PrimaryIp = "9.9.9.9",
                DohUrl = "https://9.9.9.9/dns-query",
                DotHost = "dns.quad9.net",
                BootstrapIps = ["9.9.9.9", "149.112.112.112"],
                Port = 443,
                IsBuiltin = true
            },
            new DnsServerEntry
            {
                Id = "bootstrap_google_doh",
                Name = "Google Bootstrap DoH",
                Provider = "Google",
                Protocol = DnsProtocol.DoH,
                TrustTier = TrustTier.Tier1EncryptedTrusted,
                PrimaryIp = "8.8.8.8",
                DohUrl = "https://8.8.8.8/dns-query",
                DotHost = "dns.google",
                BootstrapIps = ["8.8.8.8", "8.8.4.4"],
                Port = 443,
                IsBuiltin = true
            },
            new DnsServerEntry
            {
                Id = "bootstrap_cf_dot",
                Name = "Cloudflare Bootstrap DoT",
                Provider = "Cloudflare",
                Protocol = DnsProtocol.DoT,
                TrustTier = TrustTier.Tier1EncryptedTrusted,
                PrimaryIp = "1.1.1.1",
                DotHost = "1.1.1.1",
                BootstrapIps = ["1.1.1.1", "1.0.0.1"],
                Port = 853,
                IsBuiltin = true
            },
            new DnsServerEntry
            {
                Id = "bootstrap_quad9_dot",
                Name = "Quad9 Bootstrap DoT",
                Provider = "Quad9",
                Protocol = DnsProtocol.DoT,
                TrustTier = TrustTier.Tier1EncryptedTrusted,
                PrimaryIp = "9.9.9.9",
                DotHost = "9.9.9.9",
                BootstrapIps = ["9.9.9.9", "149.112.112.112"],
                Port = 853,
                IsBuiltin = true
            }
        ];
    }

    public static IReadOnlyList<DnsServerEntry> CreateDefaultFragmentedDohEndpoints()
    {
        return
        [
            new DnsServerEntry
            {
                Id = "bootstrap_cf_doh_frag",
                Name = "Cloudflare Bootstrap DoH (TLS-Frag)",
                Provider = "Cloudflare",
                Protocol = DnsProtocol.DoH,
                TrustTier = TrustTier.Tier1EncryptedTrusted,
                PrimaryIp = "1.1.1.1",
                DohUrl = "https://1.1.1.1/dns-query",
                DotHost = "cloudflare-dns.com",
                BootstrapIps = ["1.1.1.1", "1.0.0.1"],
                Port = 443,
                Tags = ["tls-frag"],
                IsBuiltin = true
            },
            new DnsServerEntry
            {
                Id = "bootstrap_quad9_doh_frag",
                Name = "Quad9 Bootstrap DoH (TLS-Frag)",
                Provider = "Quad9",
                Protocol = DnsProtocol.DoH,
                TrustTier = TrustTier.Tier1EncryptedTrusted,
                PrimaryIp = "9.9.9.9",
                DohUrl = "https://9.9.9.9/dns-query",
                DotHost = "dns.quad9.net",
                BootstrapIps = ["9.9.9.9"],
                Port = 443,
                Tags = ["tls-frag"],
                IsBuiltin = true
            },
            new DnsServerEntry
            {
                Id = "bootstrap_google_doh_frag",
                Name = "Google Bootstrap DoH (TLS-Frag)",
                Provider = "Google",
                Protocol = DnsProtocol.DoH,
                TrustTier = TrustTier.Tier1EncryptedTrusted,
                PrimaryIp = "8.8.8.8",
                DohUrl = "https://8.8.8.8/dns-query",
                DotHost = "dns.google",
                BootstrapIps = ["8.8.8.8"],
                Port = 443,
                Tags = ["tls-frag"],
                IsBuiltin = true
            }
        ];
    }

    public static IReadOnlyList<DnsServerEntry> CreateDefaultPlaintextFallbackEndpoints()
    {
        return
        [
            new DnsServerEntry
            {
                Id = "bootstrap_cf_udp",
                Name = "Cloudflare Plaintext Fallback",
                Provider = "Cloudflare",
                Protocol = DnsProtocol.Udp,
                TrustTier = TrustTier.Tier3CustomOrSelfHosted,
                PrimaryIp = "1.1.1.1",
                Port = 53,
                IsBuiltin = true
            },
            new DnsServerEntry
            {
                Id = "bootstrap_quad9_udp",
                Name = "Quad9 Plaintext Fallback",
                Provider = "Quad9",
                Protocol = DnsProtocol.Udp,
                TrustTier = TrustTier.Tier3CustomOrSelfHosted,
                PrimaryIp = "9.9.9.9",
                Port = 53,
                IsBuiltin = true
            },
            new DnsServerEntry
            {
                Id = "bootstrap_google_udp",
                Name = "Google Plaintext Fallback",
                Provider = "Google",
                Protocol = DnsProtocol.Udp,
                TrustTier = TrustTier.Tier3CustomOrSelfHosted,
                PrimaryIp = "8.8.8.8",
                Port = 53,
                IsBuiltin = true
            }
        ];
    }
}
