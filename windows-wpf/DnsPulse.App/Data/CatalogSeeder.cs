using System.IO;
using System.Reflection;
using DnsPulse.App.Models;

namespace DnsPulse.App.Data;

public static class CatalogSeeder
{
    private static DnsServerEntry Builtin(
        string id,
        string name,
        string provider,
        DnsProtocol protocol,
        string category,
        string primaryIp = "",
        string? secondaryIp = null,
        string? dohUrl = null,
        string? dotHost = null,
        string? smartProxyIp = null,
        int? port = null,
        string country = "GLOBAL",
        string[]? tags = null,
        string description = "",
        bool supportsBypass = false) => new()
        {
            Id = id,
            Name = name,
            Provider = provider,
            Protocol = protocol,
            PrimaryIp = primaryIp,
            SecondaryIp = secondaryIp,
            DohUrl = dohUrl,
            DotHost = dotHost,
            SmartProxyIp = smartProxyIp,
            Port = port,
            Category = category,
            Country = country,
            Tags = tags?.ToList() ?? [],
            Description = description,
            SupportsBypass = supportsBypass,
            IsBuiltin = true,
            IsFavorite = false,     // Strictly zero pre-starred built-ins
            IsSubscription = false, // Strictly zero personal subscription tokens
            IsFreeUnlimited = true
        };

    public static List<DnsServerEntry> BuildFlagships()
    {
        var list = new List<DnsServerEntry>
        {
            // 1. Bezmezhau public cluster
            Builtin("smart_bezmezhau_main", "Bezmezhau Public DNS", "Bezmezhau", DnsProtocol.DoH, "Smart-DNS",
                dohUrl: "https://dns.bezmezhau.com/dns-query", dotHost: "dns.bezmezhau.com", country: "EU",
                tags: ["smart-dns", "gemini", "aistudio", "ai", "bezmezhau", "public"],
                description: "Публичный Smart-DNS кластер Bezmezhau для AI-сервисов и обхода геоблоков", supportsBypass: true),

            // 2. MagicDNS
            Builtin("smart_magicdns_primary", "MagicDNS Primary", "MagicDNS", DnsProtocol.DoH, "Smart-DNS",
                dohUrl: "https://dns.magicdns.ru/dns-query", dotHost: "dns.magicdns.ru", country: "RU/EU",
                tags: ["smart-dns", "magicdns", "ai", "streaming"],
                description: "Публичный Smart-DNS MagicDNS (dns.magicdns.ru)", supportsBypass: true),
            Builtin("smart_magicdns_root", "MagicDNS Root", "MagicDNS", DnsProtocol.DoH, "Smart-DNS",
                dohUrl: "https://magicdns.ru/dns-query", dotHost: "magicdns.ru", country: "RU/EU",
                tags: ["smart-dns", "magicdns", "doh"],
                description: "Резервный эндпоинт MagicDNS (magicdns.ru)", supportsBypass: true),

            // 3. GeoHide DoH
            Builtin("smart_geohide_us", "GeoHide US DoH", "GeoHide", DnsProtocol.DoH, "Smart-DNS",
                dohUrl: "https://us.geohide.ru/dns-query", dotHost: "us.geohide.ru", country: "US",
                tags: ["smart-dns", "geohide", "us", "gemini", "aistudio"],
                description: "GeoHide US Smart-DNS шлюз (us.geohide.ru)", supportsBypass: true),
            Builtin("smart_geohide_eu", "GeoHide EU DoH", "GeoHide", DnsProtocol.DoH, "Smart-DNS",
                dohUrl: "https://eu.geohide.ru/dns-query", dotHost: "eu.geohide.ru", country: "EU",
                tags: ["smart-dns", "geohide", "eu", "spotify"],
                description: "GeoHide EU Smart-DNS шлюз (eu.geohide.ru)", supportsBypass: true),

            // 4. Malw.link
            Builtin("smart_malw_doh", "Malw.link Smart-DNS", "Malw.link", DnsProtocol.DoH, "Smart-DNS",
                primaryIp: "179.254.166.171", secondaryIp: "164.5.224.81",
                dohUrl: "https://dns.malw.link/dns-query", dotHost: "dns.malw.link", country: "EU",
                tags: ["smart-dns", "malw", "gemini", "chatgpt", "spotify"],
                description: "Публичный Smart-DNS dns.malw.link с динамическим списком хостов", supportsBypass: true),
            Builtin("smart_malw_udp1", "Malw.link UDP-1", "Malw.link", DnsProtocol.UDP, "Smart-DNS",
                primaryIp: "179.254.166.171", secondaryIp: "164.5.224.81", country: "EU",
                tags: ["smart-dns", "malw", "udp53"], description: "UDP 53 сервер Malw.link (179.254.166.171)", supportsBypass: true),
            Builtin("smart_malw_udp2", "Malw.link UDP-2", "Malw.link", DnsProtocol.UDP, "Smart-DNS",
                primaryIp: "164.5.224.81", secondaryIp: "179.254.166.171", country: "EU",
                tags: ["smart-dns", "malw", "udp53"], description: "Резервный UDP 53 сервер Malw.link (164.5.224.81)", supportsBypass: true),

            // 5. Comss.one
            Builtin("smart_comss_doh", "Comss.one DNS", "Comss.one", DnsProtocol.DoH, "Smart-DNS",
                primaryIp: "83.220.169.155", secondaryIp: "212.109.195.93",
                dohUrl: "https://dns.comss.one/dns-query", dotHost: "dns.comss.one", country: "RU/EU",
                tags: ["smart-dns", "comss", "ai", "xbox", "brawlstars"],
                description: "Comss.one Smart-DNS для AI, игр и стриминга", supportsBypass: true),
            Builtin("smart_comss_udp1", "Comss.one East (83.220)", "Comss.one", DnsProtocol.UDP, "Smart-DNS",
                primaryIp: "83.220.169.155", secondaryIp: "212.109.195.93", country: "RU",
                tags: ["smart-dns", "comss", "udp53"], description: "Comss.one UDP 53 (83.220.169.155)", supportsBypass: true),
            Builtin("smart_comss_udp2", "Comss.one West (212.109)", "Comss.one", DnsProtocol.UDP, "Smart-DNS",
                primaryIp: "212.109.221.20", secondaryIp: "212.109.195.93", country: "RU",
                tags: ["smart-dns", "comss", "udp53"], description: "Comss.one UDP 53 резервный (212.109.221.20)", supportsBypass: true),

            // 6. Xbox-DNS, AstraCat, Zapret.moe
            Builtin("smart_xbox_dns_doh", "Xbox-DNS.ru", "Xbox-DNS", DnsProtocol.DoH, "Игры и Регионы",
                primaryIp: "176.99.11.77", secondaryIp: "80.78.247.254",
                dohUrl: "https://xbox-dns.ru/dns-query", dotHost: "xbox-dns.ru", country: "RU",
                tags: ["xbox", "brawlstars", "gaming", "smart-dns"],
                description: "Игровой и региональный Smart-DNS Xbox-DNS.ru (176.99.11.77)", supportsBypass: true),
            Builtin("smart_xbox_dns_udp", "Xbox-DNS UDP 53", "Xbox-DNS", DnsProtocol.UDP, "Игры и Регионы",
                primaryIp: "176.99.11.77", secondaryIp: "80.78.247.254", country: "RU",
                tags: ["xbox", "gaming", "udp53"], description: "Прямой UDP 53 Xbox-DNS (176.99.11.77 / 80.78.247.254)", supportsBypass: true),
            Builtin("smart_astracat_doh", "AstraCat Smart-DNS", "AstraCat", DnsProtocol.DoH, "Smart-DNS",
                primaryIp: "185.236.104.104", secondaryIp: "135.106.217.200",
                dohUrl: "https://dns.astracat.ru/dns-query", dotHost: "dns.astracat.ru", country: "RU/EU",
                tags: ["smart-dns", "astracat", "ai"],
                description: "AstraCat Smart-DNS (185.236.104.104 / 135.106.217.200)", supportsBypass: true),
            Builtin("smart_zapret_moe", "Zapret.moe DNS", "Zapret.moe", DnsProtocol.DoH, "Smart-DNS",
                primaryIp: "83.217.211.149", dohUrl: "https://dns.zapret.moe/dns-query", dotHost: "dns.zapret.moe", country: "EU",
                tags: ["smart-dns", "zapret", "ai"], description: "Zapret.moe публичный DoH/UDP резолвер (83.217.211.149)", supportsBypass: true),

            // 7. Anti-Sanction & Gaming Smart-DNS
            Builtin("smart_shecan", "Shecan Anti-Sanction", "Shecan", DnsProtocol.DoH, "Smart-DNS",
                primaryIp: "178.22.122.100", secondaryIp: "185.51.200.2", dohUrl: "https://free.shecan.ir/dns-query", country: "IR",
                tags: ["smart-dns", "shecan", "anti-sanction"], description: "Shecan Smart-DNS для обхода санкционных ограничений", supportsBypass: true),
            Builtin("smart_403_online", "403.online DNS", "403.online", DnsProtocol.DoH, "Smart-DNS",
                primaryIp: "10.202.10.202", secondaryIp: "10.202.10.102", dohUrl: "https://dns.403.online/dns-query", country: "IR",
                tags: ["smart-dns", "403", "anti-sanction"], description: "403.online DoH Smart-DNS для обхода 403-блокировок", supportsBypass: true),
            Builtin("smart_begzar", "Begzar Smart-DNS", "Begzar", DnsProtocol.UDP, "Smart-DNS",
                primaryIp: "185.55.226.26", secondaryIp: "185.55.225.25", country: "IR",
                tags: ["smart-dns", "begzar"], description: "Begzar публичный анти-санкционный DNS", supportsBypass: true),
            Builtin("smart_electro_gaming", "Electro Gaming DNS", "Electro Team", DnsProtocol.DoH, "Игры и Регионы",
                primaryIp: "78.157.42.100", secondaryIp: "78.157.42.101", dohUrl: "https://dns.electrotm.org/dns-query", country: "IR",
                tags: ["gaming", "electro", "smart-dns", "brawlstars"], description: "Electro DNS для игр и обхода региональных ограничений", supportsBypass: true),
            Builtin("smart_radar_game", "Radar Game DNS", "Radar Game", DnsProtocol.UDP, "Игры и Регионы",
                primaryIp: "10.202.10.10", secondaryIp: "10.202.10.11", country: "IR",
                tags: ["gaming", "radar", "smart-dns"], description: "Radar Game DNS для снижения пинга и игровых серверов", supportsBypass: true),
            Builtin("smart_controld_uncensored", "Control D Uncensored", "Control D", DnsProtocol.DoH, "Скоростные",
                primaryIp: "76.76.2.0", secondaryIp: "76.76.10.0",
                dohUrl: "https://freedns.controld.com/p0", dotHost: "p0.freedns.controld.com", country: "CA",
                tags: ["controld", "uncensored", "doh", "dot"], description: "Control D Uncensored (без фильтрации, DoH + DoT)"),

            // 8. Global / Adblock / Backbone Flagships
            Builtin("global_cloudflare_1111", "Cloudflare 1.1.1.1", "Cloudflare", DnsProtocol.DoH, "Скоростные",
                primaryIp: "1.1.1.1", secondaryIp: "1.0.0.1", dohUrl: "https://cloudflare-dns.com/dns-query", dotHost: "one.one.one.one",
                country: "ANYCAST", tags: ["cloudflare", "fast", "doh", "dot", "anycast"],
                description: "Эталонный быстрый глобальный резолвер Cloudflare (1.1.1.1)"),
            Builtin("global_cloudflare_1112", "Cloudflare Security 1.1.1.2", "Cloudflare", DnsProtocol.DoH, "Скоростные",
                primaryIp: "1.1.1.2", secondaryIp: "1.0.0.2", dohUrl: "https://security.cloudflare-dns.com/dns-query", dotHost: "security.cloudflare-dns.com",
                country: "ANYCAST", tags: ["cloudflare", "malware-block"], description: "Cloudflare с защитой от фишинга и вредоносных доменов"),
            Builtin("global_google_8888", "Google Public DNS", "Google", DnsProtocol.DoH, "Магистральные",
                primaryIp: "8.8.8.8", secondaryIp: "8.8.4.4", dohUrl: "https://dns.google/dns-query", dotHost: "dns.google",
                country: "ANYCAST", tags: ["google", "backbone", "doh", "dot"], description: "Магистральный резолвер Google Public DNS (8.8.8.8)"),
            Builtin("global_quad9_9999", "Quad9 Secure", "Quad9", DnsProtocol.DoH, "Магистральные",
                primaryIp: "9.9.9.9", secondaryIp: "149.112.112.112", dohUrl: "https://dns.quad9.net/dns-query", dotHost: "dns.quad9.net",
                country: "CH", tags: ["quad9", "security", "dnssec"], description: "Швейцарский некоммерческий защищённый DNS (9.9.9.9)"),
            Builtin("global_opendns", "OpenDNS Home", "Cisco OpenDNS", DnsProtocol.DoH, "Магистральные",
                primaryIp: "208.67.222.222", secondaryIp: "208.67.220.220", dohUrl: "https://doh.opendns.com/dns-query", dotHost: "dns.opendns.com",
                country: "US", tags: ["cisco", "opendns", "backbone"], description: "Корпоративный магистральный резолвер Cisco OpenDNS"),
            Builtin("global_adguard_default", "AdGuard DNS Adblock", "AdGuard", DnsProtocol.DoH, "Антиреклама",
                primaryIp: "94.140.14.14", secondaryIp: "94.140.15.15", dohUrl: "https://dns.adguard-dns.com/dns-query", dotHost: "dns.adguard-dns.com",
                country: "CY", tags: ["adguard", "adblock", "privacy"], description: "Блокировка рекламы, трекеров и счётчиков"),
            Builtin("global_mullvad_adblock", "Mullvad Adblock", "Mullvad", DnsProtocol.DoH, "Антиреклама",
                primaryIp: "194.242.2.3", dohUrl: "https://adblock.dns.mullvad.net/dns-query", dotHost: "adblock.dns.mullvad.net",
                country: "SE", tags: ["mullvad", "adblock", "no-logs"], description: "Mullvad Encrypted DNS без логирования с блокировкой рекламы"),
            Builtin("global_nextdns", "NextDNS Anycast", "NextDNS", DnsProtocol.DoH, "Скоростные",
                primaryIp: "45.90.28.0", secondaryIp: "45.90.30.0", dohUrl: "https://dns.nextdns.io", dotHost: "dns.nextdns.io",
                country: "ANYCAST", tags: ["nextdns", "doh", "dot"], description: "Глобальная сеть низкой задержки NextDNS"),
            Builtin("global_dnssb", "DNS.SB", "DNS.SB", DnsProtocol.DoH, "Скоростные",
                primaryIp: "185.222.222.222", secondaryIp: "45.11.45.11", dohUrl: "https://doh.dns.sb/dns-query", dotHost: "dot.dns.sb",
                country: "DE", tags: ["dnssb", "privacy", "no-logs"], description: "Быстрый приватный европейский DoH/DoT DNS.SB"),
            Builtin("global_dns4eu", "DNS4EU Protective", "DNS4EU", DnsProtocol.DoH, "Магистральные",
                primaryIp: "86.54.11.1", secondaryIp: "86.54.11.100", dohUrl: "https://protective.joindns4.eu/dns-query", dotHost: "protective.joindns4.eu",
                country: "EU", tags: ["dns4eu", "europe", "gdpr"], description: "Европейская инициатива DNS4EU с защитой от угроз"),
            Builtin("global_libredns", "LibreDNS", "LibreOps", DnsProtocol.DoH, "Антиреклама",
                primaryIp: "116.202.176.26", dohUrl: "https://doh.libredns.gr/dns-query", dotHost: "dot.libredns.gr",
                country: "DE", tags: ["libredns", "privacy", "adblock"], description: "Независимый открытый DoH/DoT резолвер LibreDNS"),
            Builtin("global_uncensoreddns", "UncensoredDNS Anycast", "UncensoredDNS", DnsProtocol.DoT, "Магистральные",
                primaryIp: "91.239.100.100", secondaryIp: "89.233.43.71", dotHost: "anycast.uncensoreddns.org",
                country: "DK", tags: ["uncensoreddns", "dot", "denmark"], description: "Датский нецензурируемый DNS с поддержкой DoT"),
            Builtin("global_yandex", "Yandex DNS Basic", "Yandex", DnsProtocol.DoH, "Магистральные",
                primaryIp: "77.88.8.8", secondaryIp: "77.88.8.1", dohUrl: "https://common.dot.dns.yandex.net/dns-query", dotHost: "common.dot.dns.yandex.net",
                country: "RU", tags: ["yandex", "ru", "fast"], description: "Быстрый российский магистральный резолвер для прямого трафика"),
            Builtin("global_gcore", "GCore DNS", "GCore", DnsProtocol.DoH, "Скоростные",
                primaryIp: "95.85.95.85", secondaryIp: "2.56.220.2", dohUrl: "https://dns.gcorelabs.com/dns-query", dotHost: "dns.gcorelabs.com",
                country: "LU", tags: ["gcore", "anycast", "cdn"], description: "Глобальная edge-сеть GCore с низким пингом по СНГ и ЕС"),
            Builtin("global_common_network", "Common Network / Comodo Secure", "Common Network / Comodo", DnsProtocol.UDP, "Магистральные",
                primaryIp: "8.26.56.26", secondaryIp: "8.20.247.20", country: "US",
                tags: ["comodo", "common network", "backbone"], description: "Comodo / Common Network Secure DNS (8.26.56.26 / 8.20.247.20)"),
            Builtin("global_verisign", "Verisign Public DNS", "Verisign", DnsProtocol.UDP, "Магистральные",
                primaryIp: "64.6.64.6", secondaryIp: "64.6.65.6", country: "US",
                tags: ["verisign", "backbone", "stability"], description: "Магистральный резолвер Verisign (64.6.64.6 / 64.6.65.6)"),
            Builtin("global_level3", "Level3 / Lumen DNS", "Level3", DnsProtocol.UDP, "Магистральные",
                primaryIp: "4.2.2.1", secondaryIp: "4.2.2.2", country: "US",
                tags: ["level3", "lumen", "backbone"], description: "Классический магистральный резолвер Level3 (4.2.2.1 / 4.2.2.2)")
        };

        for (int i = 1; i <= 20; i++)
        {
            list.Add(Builtin(
                $"smart_bezmezhau_gemini{i}",
                $"Bezmezhau Gemini-{i}",
                "Bezmezhau Cluster",
                DnsProtocol.DoH,
                "Smart-DNS",
                dohUrl: $"https://gemini{i}.bezmezhau.com/dns-query",
                dotHost: $"gemini{i}.bezmezhau.com",
                country: "EU",
                tags: ["smart-dns", "gemini", "aistudio", "chatgpt", "bezmezhau"],
                description: $"Выделенный публичный узел gemini{i}.bezmezhau.com (без токена)",
                supportsBypass: true));
        }

        string[] geohideNodes = ["192.255.159.240", "192.255.159.241", "192.3.233.253", "107.175.76.134", "5.175.161.40", "143.20.64.192", "37.221.93.141", "5.175.161.3"];
        for (int i = 0; i < geohideNodes.Length; i++)
        {
            list.Add(Builtin(
                $"smart_geohide_node_{i + 1}",
                $"GeoHide Node #{i + 1}",
                "GeoHide",
                DnsProtocol.SNI443,
                "Smart-DNS",
                primaryIp: geohideNodes[i],
                dohUrl: $"smartproxy://{geohideNodes[i]}",
                smartProxyIp: geohideNodes[i],
                port: 443,
                country: i < 4 ? "US" : "EU",
                tags: ["smart-dns", "geohide", "sni443", "smartproxy"],
                description: $"SNI-прокси узел GeoHide (smartproxy://{geohideNodes[i]}:443)",
                supportsBypass: true));
        }

        (string Id, string Name, string Ip, string Country, string Desc)[] communitySniNodes =
        [
            ("smart_open_sni_nl1", "Open SNI Node NL #1", "185.236.10.37", "NL", "Нидерландский открытый SNI-узел (185.236.10.37:443) для локального туннеля."),
            ("smart_open_sni_uk2", "Open SNI Node UK #2", "82.47.171.252", "UK", "Британский открытый SNI-узел (82.47.171.252:443) для локального туннеля."),
            ("smart_open_sni_pl3", "Open SNI Node PL #3", "163.5.63.112", "PL", "Польский открытый SNI-узел (163.5.63.112:443) с низким пингом."),
            ("smart_open_sni_de4", "Open SNI Node DE #4", "5.10.223.177", "DE", "Немецкий открытый SNI-узел (5.10.223.177:443) во Франкфурте."),
            ("smart_open_sni_nord5", "Open SNI Node Nord #5", "185.194.177.120", "EU", "Североевропейский открытый SNI-узел (185.194.177.120:443)."),
            ("smart_open_sni_central6", "Open SNI Node Central #6", "87.229.95.190", "EU", "Центральноевропейский открытый SNI-узел (87.229.95.190:443).")
        ];

        foreach (var node in communitySniNodes)
        {
            list.Add(Builtin(
                node.Id,
                node.Name,
                "Community SNI Relay",
                DnsProtocol.SNI443,
                "Smart-DNS",
                primaryIp: node.Ip,
                dohUrl: $"smartproxy://{node.Ip}",
                smartProxyIp: node.Ip,
                port: 443,
                country: node.Country,
                tags: ["smart-dns", "sni443", "smartproxy", "community", node.Country.ToLowerInvariant()],
                description: node.Desc,
                supportsBypass: true));
        }

        return list;
    }

    public static List<DnsServerEntry> LoadFullCatalog(string? tsvPath = null)
    {
        var result = BuildFlagships();
        var seen = new HashSet<string>(result.Select(s => s.Id));

        string[]? lines = null;
        var diskPath = tsvPath ?? Path.Combine(AppContext.BaseDirectory, "assets", "dns_catalog_1000.tsv");
        if (File.Exists(diskPath))
        {
            lines = File.ReadAllLines(diskPath);
        }
        else
        {
            var asm = Assembly.GetExecutingAssembly();
            using var stream = asm.GetManifestResourceStream("DnsPulse.App.assets.dns_catalog_1000.tsv");
            if (stream is not null)
            {
                using var reader = new StreamReader(stream);
                lines = reader.ReadToEnd().Split(["\r\n", "\n"], StringSplitOptions.RemoveEmptyEntries);
            }
        }

        if (lines is null) return result;

        for (int i = 1; i < lines.Length; i++)
        {
            var cols = lines[i].Split('\t');
            if (cols.Length < 13) continue;
            var id = cols[0].Trim();
            if (string.IsNullOrEmpty(id) || !seen.Add(id)) continue;

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
                Tags = cols[10].Split(',', StringSplitOptions.RemoveEmptyEntries).Select(t => t.Trim()).ToList(),
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
