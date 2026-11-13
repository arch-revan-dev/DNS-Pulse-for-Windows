using System.IO;
using DnsPulse.App.Models;

namespace DnsPulse.App.Data;

public static class CatalogSeeder
{
    public static List<DnsServerEntry> BuildFlagships()
    {
        var list = new List<DnsServerEntry>
        {
            new()
            {
                Id = "smart_bezmezhau_main",
                Name = "Bezmezhau Public DNS",
                Provider = "Bezmezhau",
                Protocol = DnsProtocol.DoH,
                DohUrl = "https://dns.bezmezhau.com/dns-query",
                DotHost = "dns.bezmezhau.com",
                Category = "Smart-DNS",
                Country = "EU",
                SupportsBypass = true,
                IsBuiltin = true,
                IsFavorite = false,
                IsSubscription = false,
                IsFreeUnlimited = true
            },
            new()
            {
                Id = "smart_magicdns_primary",
                Name = "MagicDNS Primary",
                Provider = "MagicDNS",
                Protocol = DnsProtocol.DoH,
                DohUrl = "https://dns.magicdns.ru/dns-query",
                DotHost = "dns.magicdns.ru",
                Category = "Smart-DNS",
                SupportsBypass = true,
                IsBuiltin = true
            },
            new()
            {
                Id = "smart_geohide_us",
                Name = "GeoHide US DoH",
                Provider = "GeoHide",
                Protocol = DnsProtocol.DoH,
                DohUrl = "https://us.geohide.ru/dns-query",
                DotHost = "us.geohide.ru",
                Category = "Smart-DNS",
                Country = "US",
                SupportsBypass = true,
                IsBuiltin = true
            },
            new()
            {
                Id = "smart_malw_doh",
                Name = "Malw.link Smart-DNS",
                Provider = "Malw.link",
                Protocol = DnsProtocol.DoH,
                PrimaryIp = "179.254.166.171",
                SecondaryIp = "164.5.224.81",
                DohUrl = "https://dns.malw.link/dns-query",
                DotHost = "dns.malw.link",
                Category = "Smart-DNS",
                SupportsBypass = true,
                IsBuiltin = true
            },
            new()
            {
                Id = "smart_comss_doh",
                Name = "Comss.one DNS",
                Provider = "Comss.one",
                Protocol = DnsProtocol.DoH,
                PrimaryIp = "83.220.169.155",
                SecondaryIp = "212.109.195.93",
                DohUrl = "https://dns.comss.one/dns-query",
                DotHost = "dns.comss.one",
                Category = "Smart-DNS",
                SupportsBypass = true,
                IsBuiltin = true
            },
            new()
            {
                Id = "smart_xbox_dns_doh",
                Name = "Xbox-DNS.ru",
                Provider = "Xbox-DNS",
                Protocol = DnsProtocol.DoH,
                PrimaryIp = "176.99.11.77",
                SecondaryIp = "80.78.247.254",
                DohUrl = "https://xbox-dns.ru/dns-query",
                DotHost = "xbox-dns.ru",
                Category = "Игры и Регионы",
                SupportsBypass = true,
                IsBuiltin = true
            },
            new()
            {
                Id = "global_common_network",
                Name = "Common Network / Comodo Secure",
                Provider = "Common Network / Comodo",
                Protocol = DnsProtocol.UDP,
                PrimaryIp = "8.26.56.26",
                SecondaryIp = "8.20.247.20",
                Category = "Магистральные",
                IsBuiltin = true
            }
        };

        for (int i = 1; i <= 20; i++)
        {
            list.Add(new DnsServerEntry
            {
                Id = $"smart_bezmezhau_gemini{i}",
                Name = $"Bezmezhau Gemini-{i}",
                Provider = "Bezmezhau Cluster",
                Protocol = DnsProtocol.DoH,
                DohUrl = $"https://gemini{i}.bezmezhau.com/dns-query",
                DotHost = $"gemini{i}.bezmezhau.com",
                Category = "Smart-DNS",
                Country = "EU",
                SupportsBypass = true,
                IsBuiltin = true
            });
        }

        string[] geohideNodes = ["192.255.159.240", "192.255.159.241", "192.3.233.253", "107.175.76.134", "5.175.161.40", "143.20.64.192", "37.221.93.141", "5.175.161.3"];
        for (int i = 0; i < geohideNodes.Length; i++)
        {
            list.Add(new DnsServerEntry
            {
                Id = $"smart_geohide_node_{i + 1}",
                Name = $"GeoHide Node #{i + 1}",
                Provider = "GeoHide",
                Protocol = DnsProtocol.SNI443,
                PrimaryIp = geohideNodes[i],
                SmartProxyIp = geohideNodes[i],
                Port = 443,
                Category = "Smart-DNS",
                SupportsBypass = true,
                IsBuiltin = true
            });
        }

        return list;
    }

    public static List<DnsServerEntry> LoadFullCatalog(string? tsvPath = null)
    {
        var result = BuildFlagships();
        var seen = new HashSet<string>(result.Select(s => s.Id));

        var path = tsvPath ?? Path.Combine(AppContext.BaseDirectory, "assets", "dns_catalog_1000.tsv");
        if (!File.Exists(path)) return result;

        var lines = File.ReadAllLines(path);
        for (int i = 1; i < lines.Length; i++)
        {
            var cols = lines[i].Split('\t');
            if (cols.Length < 13) continue;
            var id = cols[0].Trim();
            if (!seen.Add(id)) continue;

            result.Add(new DnsServerEntry
            {
                Id = id,
                Name = cols[1].Trim(),
                Provider = cols[2].Trim(),
                Protocol = Enum.TryParse<DnsProtocol>(cols[3].Trim(), out var p) ? p : DnsProtocol.UDP,
                PrimaryIp = cols[4].Trim(),
                SecondaryIp = string.IsNullOrWhiteSpace(cols[5]) ? null : cols[5].Trim(),
                DohUrl = string.IsNullOrWhiteSpace(cols[6]) ? null : cols[6].Trim(),
                DotHost = string.IsNullOrWhiteSpace(cols[7]) ? null : cols[7].Trim(),
                Category = cols[8].Trim(),
                Country = cols[9].Trim(),
                Tags = cols[10].Split(',', StringSplitOptions.RemoveEmptyEntries).ToList(),
                Description = cols[11].Trim(),
                SupportsBypass = cols[12].Trim() == "true",
                IsBuiltin = true,
                IsFavorite = false,
                IsSubscription = false,
                IsFreeUnlimited = true
            });
        }

        return result;
    }
}
