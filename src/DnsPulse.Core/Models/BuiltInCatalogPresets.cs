using System.Globalization;
using System.Net;

namespace DnsPulse.Core.Models;

/// <summary>
/// Built-in v1.5.3 service presets, protected bypass domain lists, and flagship DNS/Smart-DNS/SNI-Proxy nodes.
/// </summary>
public static class BuiltInCatalogPresets
{
    private static readonly char[] TagSeparators = [','];

    public static IReadOnlyList<ServicePresetGroup> PresetGroups { get; } =
    [
        new ServicePresetGroup("ai", "ИИ", true),
        new ServicePresetGroup("streaming", "Стриминг"),
        new ServicePresetGroup("gaming", "Игры"),
        new ServicePresetGroup("all", "Всё"),
        new ServicePresetGroup("custom", "Свой")
    ];

    public static IReadOnlyList<DomainPresetItem> AllPresets { get; } =
    [
        new DomainPresetItem("gemini", "ai", "Gemini", "gemini.google.com", true, true),
        new DomainPresetItem("aistudio", "ai", "AI Studio", "aistudio.google.com", true, false),
        new DomainPresetItem("chatgpt", "ai", "ChatGPT", "chatgpt.com", true, false),
        new DomainPresetItem("claude", "ai", "Claude", "claude.ai", true, false),
        new DomainPresetItem("copilot", "ai", "Copilot", "copilot.microsoft.com", true, false),

        new DomainPresetItem("spotify", "streaming", "Spotify", "open.spotify.com", true, false),
        new DomainPresetItem("youtube", "streaming", "YouTube", "www.youtube.com", true, false),
        new DomainPresetItem("twitch", "streaming", "Twitch", "www.twitch.tv", true, false),
        new DomainPresetItem("netflix", "streaming", "Netflix", "www.netflix.com", true, false),

        new DomainPresetItem("xbox", "gaming", "Xbox Live", "login.live.com", true, false),
        new DomainPresetItem("brawlstars", "gaming", "Brawl Stars", "game.brawlstarsgame.com", true, false),
        new DomainPresetItem("steam", "gaming", "Steam", "store.steampowered.com", true, false),
        new DomainPresetItem("epic", "gaming", "Epic Games", "store.epicgames.com", true, false),

        new DomainPresetItem("cfping", "all", "Cloudflare Ping", "one.one.one.one", false, false),
        new DomainPresetItem("google", "all", "Google Search", "www.google.com", false, false)
    ];

    public static IReadOnlyList<string> CategoryNames { get; } =
    [
        "Все",
        "Smart-DNS",
        "Скоростные",
        "Антиреклама",
        "Игры и Регионы",
        "Магистральные",
        "Свои / Найденные"
    ];

    public static IReadOnlyList<string> BuiltinAiDomains { get; } =
    [
        "gemini.google.com",
        "aistudio.google.com",
        "ai.studio",
        "alkalimakersuite-pa.clients6.google.com",
        "alkalicore-pa.clients6.google.com",
        "webchannel-alkalimakersuite-pa.clients6.google.com",
        "generativelanguage.googleapis.com",
        "geller-pa.googleapis.com",
        "generativeai.google",
        "makersuite.google.com",
        "ai.google.dev",
        "gemini.gstatic.com",
        "bard.google.com",
        "proactivebackend-pa.googleapis.com",
        "notebooklm.google.com",
        "notebooklm.google",
        "labs.google",
        "opal.google.com",
        "jules.google.com",
        "aisandbox-pa.googleapis.com",
        "robinfrontend-pa.googleapis.com",
        "deepmind.google",
        "idx.google.com",
        "stitch.withgoogle.com",
        "clients6.google.com",
        "chatgpt.com",
        "openai.com",
        "api.openai.com",
        "auth.openai.com",
        "oaistatic.com",
        "oaiusercontent.com",
        "claude.ai",
        "anthropic.com",
        "api.anthropic.com",
        "grok.com",
        "x.ai",
        "copilot.microsoft.com",
        "sydney.bing.com",
        "perplexity.ai",
        "elevenlabs.io",
        "api.elevenlabs.io",
        "notion.so",
        "canva.com",
        "figma.com",
        "deepl.com",
        "plugins.jetbrains.com",
        "account.jetbrains.com",
        "copilot-proxy.githubusercontent.com",
        "cursor.sh",
        "cursor.com",
        "codeium.com",
        "huggingface.co"
    ];

    public static IReadOnlyList<string> BuiltinStreamingDomains { get; } =
    [
        "spotify.com",
        "open.spotify.com",
        "spclient.wg.spotify.com",
        "apresolve.spotify.com",
        "audio-ak-spotify-com.akamaized.net",
        "soundcloud.com",
        "api-v2.soundcloud.com",
        "tidal.com",
        "deezer.com",
        "twitch.tv",
        "gql.twitch.tv",
        "netflix.com"
    ];

    public static IReadOnlyList<string> BuiltinGamingDomains { get; } =
    [
        "xboxlive.com",
        "xbox.com",
        "login.live.com",
        "user.auth.xboxlive.com",
        "xsts.auth.xboxlive.com",
        "title.mgt.xboxlive.com",
        "brawlstars.com",
        "supercell.com",
        "store.supercell.com",
        "game.brawlstarsgame.com",
        "clashroyale.com",
        "clashofclans.com",
        "nvidiagrid.net",
        "geforcenow.com",
        "play.geforcenow.com",
        "playstation.com",
        "playstation.net",
        "parsec.app"
    ];

    public static IReadOnlyList<string> AllBuiltinBypassDomains { get; } = BuildCombinedBypassDomains();

    private static readonly string[] GeoHideNodes =
    [
        "192.255.159.240",
        "192.255.159.241",
        "192.3.233.253",
        "107.175.76.134",
        "5.175.161.40",
        "143.20.64.192",
        "37.221.93.141",
        "5.175.161.3"
    ];

    private static readonly (string Id, string Name, string Ip, string Country, string Desc)[] CommunitySniNodes =
    [
        ("smart_open_sni_nl1", "Open SNI Node NL #1", "185.236.10.37", "NL", "Нидерландский открытый SNI-узел (185.236.10.37:443) для локального туннеля."),
        ("smart_open_sni_uk2", "Open SNI Node UK #2", "82.47.171.252", "UK", "Британский открытый SNI-узел (82.47.171.252:443) для локального туннеля."),
        ("smart_open_sni_pl3", "Open SNI Node PL #3", "163.5.63.112", "PL", "Польский открытый SNI-узел (163.5.63.112:443) с низким пингом."),
        ("smart_open_sni_de4", "Open SNI Node DE #4", "5.10.223.177", "DE", "Немецкий открытый SNI-узел (5.10.223.177:443) во Франкфурте."),
        ("smart_open_sni_nord5", "Open SNI Node Nord #5", "185.194.177.120", "EU", "Североевропейский открытый SNI-узел (185.194.177.120:443)."),
        ("smart_open_sni_central6", "Open SNI Node Central #6", "87.229.95.190", "EU", "Центральноевропейский открытый SNI-узел (87.229.95.190:443).")
    ];

    /// <summary>
    /// Builds all 72 built-in flagship resolvers, Smart-DNS endpoints, GeoHide SNI443 nodes, and Community SNI relays.
    /// </summary>
    public static IReadOnlyList<DnsServerEntry> BuildFlagshipServers()
    {
        List<DnsServerEntry> list =
        [
            // 1. Bezmezhau public cluster
            CreateBuiltin(
                "smart_bezmezhau_main",
                "Bezmezhau Public DNS",
                "Bezmezhau",
                DnsProtocol.DoH,
                "Smart-DNS",
                dohUrl: "https://dns.bezmezhau.com/dns-query",
                dotHost: "dns.bezmezhau.com",
                country: "EU",
                tagsCsv: "smart-dns,gemini,aistudio,ai,bezmezhau,public",
                description: "Публичный Smart-DNS кластер Bezmezhau для AI-сервисов и обхода геоблоков",
                supportsBypass: true),

            // 2. MagicDNS
            CreateBuiltin(
                "smart_magicdns_primary",
                "MagicDNS Primary",
                "MagicDNS",
                DnsProtocol.DoH,
                "Smart-DNS",
                dohUrl: "https://dns.magicdns.ru/dns-query",
                dotHost: "dns.magicdns.ru",
                country: "RU/EU",
                tagsCsv: "smart-dns,magicdns,ai,streaming",
                description: "Публичный Smart-DNS MagicDNS (dns.magicdns.ru)",
                supportsBypass: true),
            CreateBuiltin(
                "smart_magicdns_root",
                "MagicDNS Root",
                "MagicDNS",
                DnsProtocol.DoH,
                "Smart-DNS",
                dohUrl: "https://magicdns.ru/dns-query",
                dotHost: "magicdns.ru",
                country: "RU/EU",
                tagsCsv: "smart-dns,magicdns,doh",
                description: "Резервный эндпоинт MagicDNS (magicdns.ru)",
                supportsBypass: true),

            // 3. GeoHide DoH
            CreateBuiltin(
                "smart_geohide_us",
                "GeoHide US DoH",
                "GeoHide",
                DnsProtocol.DoH,
                "Smart-DNS",
                dohUrl: "https://us.geohide.ru/dns-query",
                dotHost: "us.geohide.ru",
                country: "US",
                tagsCsv: "smart-dns,geohide,us,gemini,aistudio",
                description: "GeoHide US Smart-DNS шлюз (us.geohide.ru)",
                supportsBypass: true),
            CreateBuiltin(
                "smart_geohide_eu",
                "GeoHide EU DoH",
                "GeoHide",
                DnsProtocol.DoH,
                "Smart-DNS",
                dohUrl: "https://eu.geohide.ru/dns-query",
                dotHost: "eu.geohide.ru",
                country: "EU",
                tagsCsv: "smart-dns,geohide,eu,spotify",
                description: "GeoHide EU Smart-DNS шлюз (eu.geohide.ru)",
                supportsBypass: true),

            // 4. Malw.link
            CreateBuiltin(
                "smart_malw_doh",
                "Malw.link Smart-DNS",
                "Malw.link",
                DnsProtocol.DoH,
                "Smart-DNS",
                primaryIp: "179.254.166.171",
                secondaryIp: "164.5.224.81",
                dohUrl: "https://dns.malw.link/dns-query",
                dotHost: "dns.malw.link",
                country: "EU",
                tagsCsv: "smart-dns,malw,gemini,chatgpt,spotify",
                description: "Публичный Smart-DNS dns.malw.link с динамическим списком хостов",
                supportsBypass: true),
            CreateBuiltin(
                "smart_malw_udp1",
                "Malw.link UDP-1",
                "Malw.link",
                DnsProtocol.Udp,
                "Smart-DNS",
                primaryIp: "179.254.166.171",
                secondaryIp: "164.5.224.81",
                country: "EU",
                tagsCsv: "smart-dns,malw,udp53",
                description: "UDP 53 сервер Malw.link (179.254.166.171)",
                supportsBypass: true),
            CreateBuiltin(
                "smart_malw_udp2",
                "Malw.link UDP-2",
                "Malw.link",
                DnsProtocol.Udp,
                "Smart-DNS",
                primaryIp: "164.5.224.81",
                secondaryIp: "179.254.166.171",
                country: "EU",
                tagsCsv: "smart-dns,malw,udp53",
                description: "Резервный UDP 53 сервер Malw.link (164.5.224.81)",
                supportsBypass: true),

            // 5. Comss.one
            CreateBuiltin(
                "smart_comss_doh",
                "Comss.one DNS",
                "Comss.one",
                DnsProtocol.DoH,
                "Smart-DNS",
                primaryIp: "83.220.169.155",
                secondaryIp: "212.109.195.93",
                dohUrl: "https://dns.comss.one/dns-query",
                dotHost: "dns.comss.one",
                country: "RU/EU",
                tagsCsv: "smart-dns,comss,ai,xbox,brawlstars",
                description: "Comss.one Smart-DNS для AI, игр и стриминга",
                supportsBypass: true),
            CreateBuiltin(
                "smart_comss_udp1",
                "Comss.one East (83.220)",
                "Comss.one",
                DnsProtocol.Udp,
                "Smart-DNS",
                primaryIp: "83.220.169.155",
                secondaryIp: "212.109.195.93",
                country: "RU",
                tagsCsv: "smart-dns,comss,udp53",
                description: "Comss.one UDP 53 (83.220.169.155)",
                supportsBypass: true),
            CreateBuiltin(
                "smart_comss_udp2",
                "Comss.one West (212.109)",
                "Comss.one",
                DnsProtocol.Udp,
                "Smart-DNS",
                primaryIp: "212.109.221.20",
                secondaryIp: "212.109.195.93",
                country: "RU",
                tagsCsv: "smart-dns,comss,udp53",
                description: "Comss.one UDP 53 резервный (212.109.221.20)",
                supportsBypass: true),

            // 6. Xbox-DNS, AstraCat, Zapret.moe
            CreateBuiltin(
                "smart_xbox_dns_doh",
                "Xbox-DNS.ru",
                "Xbox-DNS",
                DnsProtocol.DoH,
                "Игры и Регионы",
                primaryIp: "176.99.11.77",
                secondaryIp: "80.78.247.254",
                dohUrl: "https://xbox-dns.ru/dns-query",
                dotHost: "xbox-dns.ru",
                country: "RU",
                tagsCsv: "xbox,brawlstars,gaming,smart-dns",
                description: "Игровой и региональный Smart-DNS Xbox-DNS.ru (176.99.11.77)",
                supportsBypass: true),
            CreateBuiltin(
                "smart_xbox_dns_udp",
                "Xbox-DNS UDP 53",
                "Xbox-DNS",
                DnsProtocol.Udp,
                "Игры и Регионы",
                primaryIp: "176.99.11.77",
                secondaryIp: "80.78.247.254",
                country: "RU",
                tagsCsv: "xbox,gaming,udp53",
                description: "Прямой UDP 53 Xbox-DNS (176.99.11.77 / 80.78.247.254)",
                supportsBypass: true),
            CreateBuiltin(
                "smart_astracat_doh",
                "AstraCat Smart-DNS",
                "AstraCat",
                DnsProtocol.DoH,
                "Smart-DNS",
                primaryIp: "185.236.104.104",
                secondaryIp: "135.106.217.200",
                dohUrl: "https://dns.astracat.ru/dns-query",
                dotHost: "dns.astracat.ru",
                country: "RU/EU",
                tagsCsv: "smart-dns,astracat,ai",
                description: "AstraCat Smart-DNS (185.236.104.104 / 135.106.217.200)",
                supportsBypass: true),
            CreateBuiltin(
                "smart_zapret_moe",
                "Zapret.moe DNS",
                "Zapret.moe",
                DnsProtocol.DoH,
                "Smart-DNS",
                primaryIp: "83.217.211.149",
                dohUrl: "https://dns.zapret.moe/dns-query",
                dotHost: "dns.zapret.moe",
                country: "EU",
                tagsCsv: "smart-dns,zapret,ai",
                description: "Zapret.moe публичный DoH/UDP резолвер (83.217.211.149)",
                supportsBypass: true),

            // 7. Anti-Sanction & Gaming Smart-DNS
            CreateBuiltin(
                "smart_shecan",
                "Shecan Anti-Sanction",
                "Shecan",
                DnsProtocol.DoH,
                "Smart-DNS",
                primaryIp: "178.22.122.100",
                secondaryIp: "185.51.200.2",
                dohUrl: "https://free.shecan.ir/dns-query",
                country: "IR",
                tagsCsv: "smart-dns,shecan,anti-sanction",
                description: "Shecan Smart-DNS для обхода санкционных ограничений",
                supportsBypass: true),
            CreateBuiltin(
                "smart_403_online",
                "403.online DNS",
                "403.online",
                DnsProtocol.DoH,
                "Smart-DNS",
                primaryIp: "10.202.10.202",
                secondaryIp: "10.202.10.102",
                dohUrl: "https://dns.403.online/dns-query",
                country: "IR",
                tagsCsv: "smart-dns,403,anti-sanction",
                description: "403.online DoH Smart-DNS для обхода 403-блокировок",
                supportsBypass: true),
            CreateBuiltin(
                "smart_begzar",
                "Begzar Smart-DNS",
                "Begzar",
                DnsProtocol.Udp,
                "Smart-DNS",
                primaryIp: "185.55.226.26",
                secondaryIp: "185.55.225.25",
                country: "IR",
                tagsCsv: "smart-dns,begzar",
                description: "Begzar публичный анти-санкционный DNS",
                supportsBypass: true),
            CreateBuiltin(
                "smart_electro_gaming",
                "Electro Gaming DNS",
                "Electro Team",
                DnsProtocol.DoH,
                "Игры и Регионы",
                primaryIp: "78.157.42.100",
                secondaryIp: "78.157.42.101",
                dohUrl: "https://dns.electrotm.org/dns-query",
                country: "IR",
                tagsCsv: "gaming,electro,smart-dns,brawlstars",
                description: "Electro DNS для игр и обхода региональных ограничений",
                supportsBypass: true),
            CreateBuiltin(
                "smart_radar_game",
                "Radar Game DNS",
                "Radar Game",
                DnsProtocol.Udp,
                "Игры и Регионы",
                primaryIp: "10.202.10.10",
                secondaryIp: "10.202.10.11",
                country: "IR",
                tagsCsv: "gaming,radar,smart-dns",
                description: "Radar Game DNS для снижения пинга и игровых серверов",
                supportsBypass: true),
            CreateBuiltin(
                "smart_controld_uncensored",
                "Control D Uncensored",
                "Control D",
                DnsProtocol.DoH,
                "Скоростные",
                primaryIp: "76.76.2.0",
                secondaryIp: "76.76.10.0",
                dohUrl: "https://freedns.controld.com/p0",
                dotHost: "p0.freedns.controld.com",
                country: "CA",
                tagsCsv: "controld,uncensored,doh,dot",
                description: "Control D Uncensored (без фильтрации, DoH + DoT)"),

            // 8. Global / Adblock / Backbone Flagships
            CreateBuiltin(
                "global_cloudflare_1111",
                "Cloudflare 1.1.1.1",
                "Cloudflare",
                DnsProtocol.DoH,
                "Скоростные",
                primaryIp: "1.1.1.1",
                secondaryIp: "1.0.0.1",
                dohUrl: "https://cloudflare-dns.com/dns-query",
                dotHost: "one.one.one.one",
                country: "ANYCAST",
                tagsCsv: "cloudflare,fast,doh,dot,anycast",
                description: "Эталонный быстрый глобальный резолвер Cloudflare (1.1.1.1)"),
            CreateBuiltin(
                "global_cloudflare_1112",
                "Cloudflare Security 1.1.1.2",
                "Cloudflare",
                DnsProtocol.DoH,
                "Скоростные",
                primaryIp: "1.1.1.2",
                secondaryIp: "1.0.0.2",
                dohUrl: "https://security.cloudflare-dns.com/dns-query",
                dotHost: "security.cloudflare-dns.com",
                country: "ANYCAST",
                tagsCsv: "cloudflare,malware-block",
                description: "Cloudflare с защитой от фишинга и вредоносных доменов"),
            CreateBuiltin(
                "global_google_8888",
                "Google Public DNS",
                "Google",
                DnsProtocol.DoH,
                "Магистральные",
                primaryIp: "8.8.8.8",
                secondaryIp: "8.8.4.4",
                dohUrl: "https://dns.google/dns-query",
                dotHost: "dns.google",
                country: "ANYCAST",
                tagsCsv: "google,backbone,doh,dot",
                description: "Магистральный резолвер Google Public DNS (8.8.8.8)"),
            CreateBuiltin(
                "global_quad9_9999",
                "Quad9 Secure",
                "Quad9",
                DnsProtocol.DoH,
                "Магистральные",
                primaryIp: "9.9.9.9",
                secondaryIp: "149.112.112.112",
                dohUrl: "https://dns.quad9.net/dns-query",
                dotHost: "dns.quad9.net",
                country: "CH",
                tagsCsv: "quad9,security,dnssec",
                description: "Швейцарский некоммерческий защищённый DNS (9.9.9.9)"),
            CreateBuiltin(
                "global_opendns",
                "OpenDNS Home",
                "Cisco OpenDNS",
                DnsProtocol.DoH,
                "Магистральные",
                primaryIp: "208.67.222.222",
                secondaryIp: "208.67.220.220",
                dohUrl: "https://doh.opendns.com/dns-query",
                dotHost: "dns.opendns.com",
                country: "US",
                tagsCsv: "cisco,opendns,backbone",
                description: "Корпоративный магистральный резолвер Cisco OpenDNS"),
            CreateBuiltin(
                "global_adguard_default",
                "AdGuard DNS Adblock",
                "AdGuard",
                DnsProtocol.DoH,
                "Антиреклама",
                primaryIp: "94.140.14.14",
                secondaryIp: "94.140.15.15",
                dohUrl: "https://dns.adguard-dns.com/dns-query",
                dotHost: "dns.adguard-dns.com",
                country: "CY",
                tagsCsv: "adguard,adblock,privacy",
                description: "Блокировка рекламы, трекеров и счётчиков"),
            CreateBuiltin(
                "global_mullvad_adblock",
                "Mullvad Adblock",
                "Mullvad",
                DnsProtocol.DoH,
                "Антиреклама",
                primaryIp: "194.242.2.3",
                dohUrl: "https://adblock.dns.mullvad.net/dns-query",
                dotHost: "adblock.dns.mullvad.net",
                country: "SE",
                tagsCsv: "mullvad,adblock,no-logs",
                description: "Mullvad Encrypted DNS без логирования с блокировкой рекламы"),
            CreateBuiltin(
                "global_nextdns",
                "NextDNS Anycast",
                "NextDNS",
                DnsProtocol.DoH,
                "Скоростные",
                primaryIp: "45.90.28.0",
                secondaryIp: "45.90.30.0",
                dohUrl: "https://dns.nextdns.io",
                dotHost: "dns.nextdns.io",
                country: "ANYCAST",
                tagsCsv: "nextdns,doh,dot",
                description: "Глобальная сеть низкой задержки NextDNS"),
            CreateBuiltin(
                "global_dnssb",
                "DNS.SB",
                "DNS.SB",
                DnsProtocol.DoH,
                "Скоростные",
                primaryIp: "185.222.222.222",
                secondaryIp: "45.11.45.11",
                dohUrl: "https://doh.dns.sb/dns-query",
                dotHost: "dot.dns.sb",
                country: "DE",
                tagsCsv: "dnssb,privacy,no-logs",
                description: "Быстрый приватный европейский DoH/DoT DNS.SB"),
            CreateBuiltin(
                "global_dns4eu",
                "DNS4EU Protective",
                "DNS4EU",
                DnsProtocol.DoH,
                "Магистральные",
                primaryIp: "86.54.11.1",
                secondaryIp: "86.54.11.100",
                dohUrl: "https://protective.joindns4.eu/dns-query",
                dotHost: "protective.joindns4.eu",
                country: "EU",
                tagsCsv: "dns4eu,europe,gdpr",
                description: "Европейская инициатива DNS4EU с защитой от угроз"),
            CreateBuiltin(
                "global_libredns",
                "LibreDNS",
                "LibreOps",
                DnsProtocol.DoH,
                "Антиреклама",
                primaryIp: "116.202.176.26",
                dohUrl: "https://doh.libredns.gr/dns-query",
                dotHost: "dot.libredns.gr",
                country: "DE",
                tagsCsv: "libredns,privacy,adblock",
                description: "Независимый открытый DoH/DoT резолвер LibreDNS"),
            CreateBuiltin(
                "global_uncensoreddns",
                "UncensoredDNS Anycast",
                "UncensoredDNS",
                DnsProtocol.DoT,
                "Магистральные",
                primaryIp: "91.239.100.100",
                secondaryIp: "89.233.43.71",
                dotHost: "anycast.uncensoreddns.org",
                country: "DK",
                tagsCsv: "uncensoreddns,dot,denmark",
                description: "Датский нецензурируемый DNS с поддержкой DoT"),
            CreateBuiltin(
                "global_yandex",
                "Yandex DNS Basic",
                "Yandex",
                DnsProtocol.DoH,
                "Магистральные",
                primaryIp: "77.88.8.8",
                secondaryIp: "77.88.8.1",
                dohUrl: "https://common.dot.dns.yandex.net/dns-query",
                dotHost: "common.dot.dns.yandex.net",
                country: "RU",
                tagsCsv: "yandex,ru,fast",
                description: "Быстрый российский магистральный резолвер для прямого трафика"),
            CreateBuiltin(
                "global_gcore",
                "GCore DNS",
                "GCore",
                DnsProtocol.DoH,
                "Скоростные",
                primaryIp: "95.85.95.85",
                secondaryIp: "2.56.220.2",
                dohUrl: "https://dns.gcorelabs.com/dns-query",
                dotHost: "dns.gcorelabs.com",
                country: "LU",
                tagsCsv: "gcore,anycast,cdn",
                description: "Глобальная edge-сеть GCore с низким пингом по СНГ и ЕС"),
            CreateBuiltin(
                "global_common_network",
                "Common Network / Comodo Secure",
                "Common Network / Comodo",
                DnsProtocol.Udp,
                "Магистральные",
                primaryIp: "8.26.56.26",
                secondaryIp: "8.20.247.20",
                country: "US",
                tagsCsv: "comodo,common network,backbone",
                description: "Comodo / Common Network Secure DNS (8.26.56.26 / 8.20.247.20)"),
            CreateBuiltin(
                "global_verisign",
                "Verisign Public DNS",
                "Verisign",
                DnsProtocol.Udp,
                "Магистральные",
                primaryIp: "64.6.64.6",
                secondaryIp: "64.6.65.6",
                country: "US",
                tagsCsv: "verisign,backbone,stability",
                description: "Магистральный резолвер Verisign (64.6.64.6 / 64.6.65.6)"),
            CreateBuiltin(
                "global_level3",
                "Level3 / Lumen DNS",
                "Level3",
                DnsProtocol.Udp,
                "Магистральные",
                primaryIp: "4.2.2.1",
                secondaryIp: "4.2.2.2",
                country: "US",
                tagsCsv: "level3,lumen,backbone",
                description: "Классический магистральный резолвер Level3 (4.2.2.1 / 4.2.2.2)")
        ];

        for (int index = 1; index <= 20; index++)
        {
            list.Add(CreateBuiltin(
                string.Create(CultureInfo.InvariantCulture, $"smart_bezmezhau_gemini{index}"),
                string.Create(CultureInfo.InvariantCulture, $"Bezmezhau Gemini-{index}"),
                "Bezmezhau Cluster",
                DnsProtocol.DoH,
                "Smart-DNS",
                dohUrl: string.Create(CultureInfo.InvariantCulture, $"https://gemini{index}.bezmezhau.com/dns-query"),
                dotHost: string.Create(CultureInfo.InvariantCulture, $"gemini{index}.bezmezhau.com"),
                country: "EU",
                tagsCsv: "smart-dns,gemini,aistudio,chatgpt,bezmezhau",
                description: string.Create(CultureInfo.InvariantCulture, $"Выделенный публичный узел gemini{index}.bezmezhau.com (без токена)"),
                supportsBypass: true));
        }

        for (int index = 0; index < GeoHideNodes.Length; index++)
        {
            string ip = GeoHideNodes[index];
            list.Add(CreateBuiltin(
                string.Create(CultureInfo.InvariantCulture, $"smart_geohide_node_{index + 1}"),
                string.Create(CultureInfo.InvariantCulture, $"GeoHide Node #{index + 1}"),
                "GeoHide",
                DnsProtocol.SniProxy,
                "Smart-DNS",
                primaryIp: ip,
                dohUrl: string.Concat("smartproxy://", ip),
                smartProxyIp: ip,
                port: 443,
                country: index < 4 ? "US" : "EU",
                tagsCsv: "smart-dns,geohide,sni443,smartproxy",
                description: string.Create(CultureInfo.InvariantCulture, $"SNI-прокси узел GeoHide (smartproxy://{ip}:443)"),
                supportsBypass: true));
        }

        foreach ((string id, string name, string ip, string country, string desc) in CommunitySniNodes)
        {
            list.Add(CreateBuiltin(
                id,
                name,
                "Community SNI Relay",
                DnsProtocol.SniProxy,
                "Smart-DNS",
                primaryIp: ip,
                dohUrl: string.Concat("smartproxy://", ip),
                smartProxyIp: ip,
                port: 443,
                country: country,
                tagsCsv: string.Concat("smart-dns,sni443,smartproxy,community,", ToAsciiLower(country)),
                description: desc,
                supportsBypass: true));
        }

        return list;
    }

    internal static IReadOnlyList<string> BuildBootstrapIpList(string? primaryIp, string? secondaryIp)
    {
        List<string> ips = new(2);
        if (!string.IsNullOrWhiteSpace(primaryIp) && IPAddress.TryParse(primaryIp.Trim(), out _))
        {
            ips.Add(primaryIp.Trim());
        }

        if (!string.IsNullOrWhiteSpace(secondaryIp) && IPAddress.TryParse(secondaryIp.Trim(), out _))
        {
            string trimmedSecondary = secondaryIp.Trim();
            if (!ips.Contains(trimmedSecondary, StringComparer.OrdinalIgnoreCase))
            {
                ips.Add(trimmedSecondary);
            }
        }

        return ips;
    }

    private static DnsServerEntry CreateBuiltin(
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
        string tagsCsv = "",
        string description = "",
        bool supportsBypass = false)
    {
        TrustTier trustTier = CatalogTsvLoader.AssignBuiltinTrustTier(protocol, supportsBypass);
        IReadOnlyList<string> bootstrapIps = BuildBootstrapIpList(primaryIp, secondaryIp);
        string[] tags = string.IsNullOrWhiteSpace(tagsCsv)
            ? []
            : tagsCsv.Split(TagSeparators, StringSplitOptions.RemoveEmptyEntries);

        return new DnsServerEntry
        {
            Id = id,
            Name = name,
            Provider = provider,
            Protocol = protocol,
            TrustTier = trustTier,
            PrimaryIp = primaryIp,
            SecondaryIp = secondaryIp,
            DohUrl = dohUrl,
            DotHost = dotHost,
            SmartProxyIp = smartProxyIp,
            BootstrapIps = bootstrapIps,
            Port = port,
            Category = category,
            Country = country,
            Tags = tags,
            Description = description,
            SupportsBypass = supportsBypass,
            IsBuiltin = true,
            IsFavorite = false,
            IsSubscription = false,
            IsFreeUnlimited = true
        };
    }

    private static string[] BuildCombinedBypassDomains()
    {
        HashSet<string> seen = new(StringComparer.OrdinalIgnoreCase);
        List<string> combined = new(BuiltinAiDomains.Count + BuiltinStreamingDomains.Count + BuiltinGamingDomains.Count);

        AddUniqueDomains(BuiltinAiDomains, seen, combined);
        AddUniqueDomains(BuiltinStreamingDomains, seen, combined);
        AddUniqueDomains(BuiltinGamingDomains, seen, combined);

        return [.. combined];
    }

    private static void AddUniqueDomains(IReadOnlyList<string> source, HashSet<string> seen, List<string> target)
    {
        foreach (string domain in source)
        {
            if (seen.Add(domain))
            {
                target.Add(domain);
            }
        }
    }

    private static string ToAsciiLower(string value)
    {
        return string.Create(value.Length, value, static (span, source) =>
        {
            for (int index = 0; index < source.Length; index++)
            {
                char ch = source[index];
                span[index] = ch is >= 'A' and <= 'Z' ? (char)(ch + 32) : ch;
            }
        });
    }
}
