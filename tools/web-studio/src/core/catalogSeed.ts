import { DnsCategory, DnsProtocol, DnsServer } from './types';

function builtin(
  partial: Partial<DnsServer> & {
    id: string;
    name: string;
    provider: string;
    protocol: DnsProtocol;
    category: DnsCategory;
  }
): DnsServer {
  return {
    id: partial.id,
    name: partial.name,
    provider: partial.provider,
    protocol: partial.protocol,
    primaryIp: partial.primaryIp ?? '',
    secondaryIp: partial.secondaryIp,
    dohUrl: partial.dohUrl,
    dotHost: partial.dotHost,
    smartProxyIp: partial.smartProxyIp,
    port: partial.port,
    category: partial.category,
    country: partial.country ?? 'GLOBAL',
    tags: partial.tags ?? [],
    description: partial.description ?? '',
    supportsBypass: partial.supportsBypass ?? false,
    isBuiltin: true,
    isFavorite: false, // Rule: ZERO pre-starred built-in servers
    isSubscription: false, // Rule: ZERO personal subscription tokens in built-in DB
    isFreeUnlimited: true,
    lastLatencyMs: null,
    minLatencyMs: null,
    avgLatencyMs: null,
    jitterMs: null,
    lastTps: null,
    verdict: 'UNCHECKED',
    verdictReason: 'Не проверялся',
    resolvedIps: [],
    companionPassed: null,
    port443Ok: null,
    httpStatus: null,
    lastCheckedDomain: null,
    lastCheckedAt: null,
    historyMs: [],
  };
}

export function getFlagshipBuiltinServers(): DnsServer[] {
  const servers: DnsServer[] = [];

  // 1. Public Bezmezhau cluster (NO personal tokens)
  servers.push(
    builtin({
      id: 'smart_bezmezhau_main',
      name: 'Bezmezhau Public DNS',
      provider: 'Bezmezhau',
      protocol: 'DoH',
      dohUrl: 'https://dns.bezmezhau.com/dns-query',
      dotHost: 'dns.bezmezhau.com',
      category: 'Smart-DNS',
      country: 'EU',
      tags: ['smart-dns', 'gemini', 'aistudio', 'ai', 'bezmezhau', 'public'],
      description: 'Публичный Smart-DNS кластер Bezmezhau для AI-сервисов и обхода геоблоков',
      supportsBypass: true,
    })
  );

  for (let i = 1; i <= 20; i++) {
    servers.push(
      builtin({
        id: `smart_bezmezhau_gemini${i}`,
        name: `Bezmezhau Gemini-${i}`,
        provider: 'Bezmezhau Cluster',
        protocol: 'DoH',
        dohUrl: `https://gemini${i}.bezmezhau.com/dns-query`,
        dotHost: `gemini${i}.bezmezhau.com`,
        category: 'Smart-DNS',
        country: 'EU',
        tags: ['smart-dns', 'gemini', 'aistudio', 'chatgpt', 'bezmezhau'],
        description: `Выделенный публичный узел gemini${i}.bezmezhau.com (без токена)`,
        supportsBypass: true,
      })
    );
  }

  // 2. MagicDNS
  servers.push(
    builtin({
      id: 'smart_magicdns_primary',
      name: 'MagicDNS Primary',
      provider: 'MagicDNS',
      protocol: 'DoH',
      dohUrl: 'https://dns.magicdns.ru/dns-query',
      dotHost: 'dns.magicdns.ru',
      category: 'Smart-DNS',
      country: 'RU/EU',
      tags: ['smart-dns', 'magicdns', 'ai', 'streaming'],
      description: 'Публичный Smart-DNS MagicDNS (dns.magicdns.ru)',
      supportsBypass: true,
    }),
    builtin({
      id: 'smart_magicdns_root',
      name: 'MagicDNS Root',
      provider: 'MagicDNS',
      protocol: 'DoH',
      dohUrl: 'https://magicdns.ru/dns-query',
      dotHost: 'magicdns.ru',
      category: 'Smart-DNS',
      country: 'RU/EU',
      tags: ['smart-dns', 'magicdns', 'doh'],
      description: 'Резервный эндпоинт MagicDNS (magicdns.ru)',
      supportsBypass: true,
    })
  );

  // 3. GeoHide DoH + Proxy Nodes
  servers.push(
    builtin({
      id: 'smart_geohide_us',
      name: 'GeoHide US DoH',
      provider: 'GeoHide',
      protocol: 'DoH',
      dohUrl: 'https://us.geohide.ru/dns-query',
      dotHost: 'us.geohide.ru',
      category: 'Smart-DNS',
      country: 'US',
      tags: ['smart-dns', 'geohide', 'us', 'gemini', 'aistudio'],
      description: 'GeoHide US Smart-DNS шлюз (us.geohide.ru)',
      supportsBypass: true,
    }),
    builtin({
      id: 'smart_geohide_eu',
      name: 'GeoHide EU DoH',
      provider: 'GeoHide',
      protocol: 'DoH',
      dohUrl: 'https://eu.geohide.ru/dns-query',
      dotHost: 'eu.geohide.ru',
      category: 'Smart-DNS',
      country: 'EU',
      tags: ['smart-dns', 'geohide', 'eu', 'spotify'],
      description: 'GeoHide EU Smart-DNS шлюз (eu.geohide.ru)',
      supportsBypass: true,
    })
  );

  const geohideNodes = [
    '192.255.159.240',
    '192.255.159.241',
    '192.3.233.253',
    '107.175.76.134',
    '5.175.161.40',
    '143.20.64.192',
    '37.221.93.141',
    '5.175.161.3',
  ];
  geohideNodes.forEach((ip, idx) => {
    servers.push(
      builtin({
        id: `smart_geohide_node_${idx + 1}`,
        name: `GeoHide Node #${idx + 1}`,
        provider: 'GeoHide',
        protocol: 'SNI443',
        primaryIp: ip,
        smartProxyIp: ip,
        port: 443,
        category: 'Smart-DNS',
        country: idx < 4 ? 'US' : 'EU',
        tags: ['smart-dns', 'geohide', 'sni443', 'smartproxy'],
        description: `SNI-прокси узел GeoHide (smartproxy://${ip}:443)`,
        supportsBypass: true,
      })
    );
  });

  // 4. Malw.link
  servers.push(
    builtin({
      id: 'smart_malw_doh',
      name: 'Malw.link Smart-DNS',
      provider: 'Malw.link',
      protocol: 'DoH',
      primaryIp: '179.254.166.171',
      secondaryIp: '164.5.224.81',
      dohUrl: 'https://dns.malw.link/dns-query',
      dotHost: 'dns.malw.link',
      category: 'Smart-DNS',
      country: 'EU',
      tags: ['smart-dns', 'malw', 'gemini', 'chatgpt', 'spotify'],
      description: 'Публичный Smart-DNS dns.malw.link с динамическим списком хостов',
      supportsBypass: true,
    }),
    builtin({
      id: 'smart_malw_udp1',
      name: 'Malw.link UDP-1',
      provider: 'Malw.link',
      protocol: 'UDP',
      primaryIp: '179.254.166.171',
      secondaryIp: '164.5.224.81',
      category: 'Smart-DNS',
      country: 'EU',
      tags: ['smart-dns', 'malw', 'udp53'],
      description: 'UDP 53 сервер Malw.link (179.254.166.171)',
      supportsBypass: true,
    }),
    builtin({
      id: 'smart_malw_udp2',
      name: 'Malw.link UDP-2',
      provider: 'Malw.link',
      protocol: 'UDP',
      primaryIp: '164.5.224.81',
      secondaryIp: '179.254.166.171',
      category: 'Smart-DNS',
      country: 'EU',
      tags: ['smart-dns', 'malw', 'udp53'],
      description: 'Резервный UDP 53 сервер Malw.link (164.5.224.81)',
      supportsBypass: true,
    })
  );

  // 5. Comss.one
  servers.push(
    builtin({
      id: 'smart_comss_doh',
      name: 'Comss.one DNS',
      provider: 'Comss.one',
      protocol: 'DoH',
      primaryIp: '83.220.169.155',
      secondaryIp: '212.109.195.93',
      dohUrl: 'https://dns.comss.one/dns-query',
      dotHost: 'dns.comss.one',
      category: 'Smart-DNS',
      country: 'RU/EU',
      tags: ['smart-dns', 'comss', 'ai', 'xbox', 'brawlstars'],
      description: 'Comss.one Smart-DNS для AI, игр и стриминга',
      supportsBypass: true,
    }),
    builtin({
      id: 'smart_comss_udp1',
      name: 'Comss.one East (83.220)',
      provider: 'Comss.one',
      protocol: 'UDP',
      primaryIp: '83.220.169.155',
      secondaryIp: '212.109.195.93',
      category: 'Smart-DNS',
      country: 'RU',
      tags: ['smart-dns', 'comss', 'udp53'],
      description: 'Comss.one UDP 53 (83.220.169.155)',
      supportsBypass: true,
    }),
    builtin({
      id: 'smart_comss_udp2',
      name: 'Comss.one West (212.109)',
      provider: 'Comss.one',
      protocol: 'UDP',
      primaryIp: '212.109.221.20',
      secondaryIp: '212.109.195.93',
      category: 'Smart-DNS',
      country: 'RU',
      tags: ['smart-dns', 'comss', 'udp53'],
      description: 'Comss.one UDP 53 резервный (212.109.221.20)',
      supportsBypass: true,
    })
  );

  // 6. Xbox-DNS, AstraCat, Zapret.moe
  servers.push(
    builtin({
      id: 'smart_xbox_dns_doh',
      name: 'Xbox-DNS.ru',
      provider: 'Xbox-DNS',
      protocol: 'DoH',
      primaryIp: '176.99.11.77',
      secondaryIp: '80.78.247.254',
      dohUrl: 'https://xbox-dns.ru/dns-query',
      dotHost: 'xbox-dns.ru',
      category: 'Игры и Регионы',
      country: 'RU',
      tags: ['xbox', 'brawlstars', 'gaming', 'smart-dns'],
      description: 'Игровой и региональный Smart-DNS Xbox-DNS.ru (176.99.11.77)',
      supportsBypass: true,
    }),
    builtin({
      id: 'smart_xbox_dns_udp',
      name: 'Xbox-DNS UDP 53',
      provider: 'Xbox-DNS',
      protocol: 'UDP',
      primaryIp: '176.99.11.77',
      secondaryIp: '80.78.247.254',
      category: 'Игры и Регионы',
      country: 'RU',
      tags: ['xbox', 'gaming', 'udp53'],
      description: 'Прямой UDP 53 Xbox-DNS (176.99.11.77 / 80.78.247.254)',
      supportsBypass: true,
    }),
    builtin({
      id: 'smart_astracat_doh',
      name: 'AstraCat Smart-DNS',
      provider: 'AstraCat',
      protocol: 'DoH',
      primaryIp: '185.236.104.104',
      secondaryIp: '135.106.217.200',
      dohUrl: 'https://dns.astracat.ru/dns-query',
      dotHost: 'dns.astracat.ru',
      category: 'Smart-DNS',
      country: 'RU/EU',
      tags: ['smart-dns', 'astracat', 'ai'],
      description: 'AstraCat Smart-DNS (185.236.104.104 / 135.106.217.200)',
      supportsBypass: true,
    }),
    builtin({
      id: 'smart_zapret_moe',
      name: 'Zapret.moe DNS',
      provider: 'Zapret.moe',
      protocol: 'DoH',
      primaryIp: '83.217.211.149',
      dohUrl: 'https://dns.zapret.moe/dns-query',
      dotHost: 'dns.zapret.moe',
      category: 'Smart-DNS',
      country: 'EU',
      tags: ['smart-dns', 'zapret', 'ai'],
      description: 'Zapret.moe публичный DoH/UDP резолвер (83.217.211.149)',
      supportsBypass: true,
    })
  );

  // 7. Shecan, 403.online, Begzar, Electro, Radar Game, Control D Uncensored
  servers.push(
    builtin({
      id: 'smart_shecan',
      name: 'Shecan Anti-Sanction',
      provider: 'Shecan',
      protocol: 'DoH',
      primaryIp: '178.22.122.100',
      secondaryIp: '185.51.200.2',
      dohUrl: 'https://free.shecan.ir/dns-query',
      category: 'Smart-DNS',
      country: 'IR',
      tags: ['smart-dns', 'shecan', 'anti-sanction'],
      description: 'Shecan Smart-DNS для обхода санкционных ограничений',
      supportsBypass: true,
    }),
    builtin({
      id: 'smart_403_online',
      name: '403.online DNS',
      provider: '403.online',
      protocol: 'DoH',
      primaryIp: '10.202.10.202',
      secondaryIp: '10.202.10.102',
      dohUrl: 'https://dns.403.online/dns-query',
      category: 'Smart-DNS',
      country: 'IR',
      tags: ['smart-dns', '403', 'anti-sanction'],
      description: '403.online DoH Smart-DNS для обхода 403-блокировок',
      supportsBypass: true,
    }),
    builtin({
      id: 'smart_begzar',
      name: 'Begzar Smart-DNS',
      provider: 'Begzar',
      protocol: 'UDP',
      primaryIp: '185.55.226.26',
      secondaryIp: '185.55.225.25',
      category: 'Smart-DNS',
      country: 'IR',
      tags: ['smart-dns', 'begzar'],
      description: 'Begzar публичный анти-санкционный DNS',
      supportsBypass: true,
    }),
    builtin({
      id: 'smart_electro_gaming',
      name: 'Electro Gaming DNS',
      provider: 'Electro Team',
      protocol: 'DoH',
      primaryIp: '78.157.42.100',
      secondaryIp: '78.157.42.101',
      dohUrl: 'https://dns.electrotm.org/dns-query',
      category: 'Игры и Регионы',
      country: 'IR',
      tags: ['gaming', 'electro', 'smart-dns', 'brawlstars'],
      description: 'Electro DNS для игр и обхода региональных ограничений',
      supportsBypass: true,
    }),
    builtin({
      id: 'smart_radar_game',
      name: 'Radar Game DNS',
      provider: 'Radar Game',
      protocol: 'UDP',
      primaryIp: '10.202.10.10',
      secondaryIp: '10.202.10.11',
      category: 'Игры и Регионы',
      country: 'IR',
      tags: ['gaming', 'radar', 'smart-dns'],
      description: 'Radar Game DNS для снижения пинга и игровых серверов',
      supportsBypass: true,
    }),
    builtin({
      id: 'smart_controld_uncensored',
      name: 'Control D Uncensored',
      provider: 'Control D',
      protocol: 'DoH',
      primaryIp: '76.76.2.0',
      secondaryIp: '76.76.10.0',
      dohUrl: 'https://freedns.controld.com/p0',
      dotHost: 'p0.freedns.controld.com',
      category: 'Скоростные',
      country: 'CA',
      tags: ['controld', 'uncensored', 'doh', 'dot'],
      description: 'Control D Uncensored (без фильтрации, DoH + DoT)',
      supportsBypass: false,
    })
  );

  // 8. Global / Adblock / Gaming / Backbone Flagships (including Common Network / Comodo, Verisign, Level3)
  servers.push(
    builtin({
      id: 'global_cloudflare_1111',
      name: 'Cloudflare 1.1.1.1',
      provider: 'Cloudflare',
      protocol: 'DoH',
      primaryIp: '1.1.1.1',
      secondaryIp: '1.0.0.1',
      dohUrl: 'https://cloudflare-dns.com/dns-query',
      dotHost: 'one.one.one.one',
      category: 'Скоростные',
      country: 'ANYCAST',
      tags: ['cloudflare', 'fast', 'doh', 'dot', 'anycast'],
      description: 'Эталонный быстрый глобальный резолвер Cloudflare (1.1.1.1)',
      supportsBypass: false,
    }),
    builtin({
      id: 'global_cloudflare_1112',
      name: 'Cloudflare Security 1.1.1.2',
      provider: 'Cloudflare',
      protocol: 'DoH',
      primaryIp: '1.1.1.2',
      secondaryIp: '1.0.0.2',
      dohUrl: 'https://security.cloudflare-dns.com/dns-query',
      dotHost: 'security.cloudflare-dns.com',
      category: 'Скоростные',
      country: 'ANYCAST',
      tags: ['cloudflare', 'malware-block'],
      description: 'Cloudflare с защитой от фишинга и вредоносных доменов',
      supportsBypass: false,
    }),
    builtin({
      id: 'global_google_8888',
      name: 'Google Public DNS',
      provider: 'Google',
      protocol: 'DoH',
      primaryIp: '8.8.8.8',
      secondaryIp: '8.8.4.4',
      dohUrl: 'https://dns.google/dns-query',
      dotHost: 'dns.google',
      category: 'Магистральные',
      country: 'ANYCAST',
      tags: ['google', 'backbone', 'doh', 'dot'],
      description: 'Магистральный резолвер Google Public DNS (8.8.8.8)',
      supportsBypass: false,
    }),
    builtin({
      id: 'global_quad9_9999',
      name: 'Quad9 Secure',
      provider: 'Quad9',
      protocol: 'DoH',
      primaryIp: '9.9.9.9',
      secondaryIp: '149.112.112.112',
      dohUrl: 'https://dns.quad9.net/dns-query',
      dotHost: 'dns.quad9.net',
      category: 'Магистральные',
      country: 'CH',
      tags: ['quad9', 'security', 'dnssec'],
      description: 'Швейцарский некоммерческий защищённый DNS (9.9.9.9)',
      supportsBypass: false,
    }),
    builtin({
      id: 'global_opendns',
      name: 'OpenDNS Home',
      provider: 'Cisco OpenDNS',
      protocol: 'DoH',
      primaryIp: '208.67.222.222',
      secondaryIp: '208.67.220.220',
      dohUrl: 'https://doh.opendns.com/dns-query',
      dotHost: 'dns.opendns.com',
      category: 'Магистральные',
      country: 'US',
      tags: ['cisco', 'opendns', 'backbone'],
      description: 'Корпоративный магистральный резолвер Cisco OpenDNS',
      supportsBypass: false,
    }),
    builtin({
      id: 'global_adguard_default',
      name: 'AdGuard DNS Adblock',
      provider: 'AdGuard',
      protocol: 'DoH',
      primaryIp: '94.140.14.14',
      secondaryIp: '94.140.15.15',
      dohUrl: 'https://dns.adguard-dns.com/dns-query',
      dotHost: 'dns.adguard-dns.com',
      category: 'Антиреклама',
      country: 'CY',
      tags: ['adguard', 'adblock', 'privacy'],
      description: 'Блокировка рекламы, трекеров и счётчиков',
      supportsBypass: false,
    }),
    builtin({
      id: 'global_mullvad_adblock',
      name: 'Mullvad Adblock',
      provider: 'Mullvad',
      protocol: 'DoH',
      primaryIp: '194.242.2.3',
      dohUrl: 'https://adblock.dns.mullvad.net/dns-query',
      dotHost: 'adblock.dns.mullvad.net',
      category: 'Антиреклама',
      country: 'SE',
      tags: ['mullvad', 'adblock', 'no-logs'],
      description: 'Mullvad Encrypted DNS без логирования с блокировкой рекламы',
      supportsBypass: false,
    }),
    builtin({
      id: 'global_nextdns',
      name: 'NextDNS Anycast',
      provider: 'NextDNS',
      protocol: 'DoH',
      primaryIp: '45.90.28.0',
      secondaryIp: '45.90.30.0',
      dohUrl: 'https://dns.nextdns.io',
      dotHost: 'dns.nextdns.io',
      category: 'Скоростные',
      country: 'ANYCAST',
      tags: ['nextdns', 'doh', 'dot'],
      description: 'Глобальная сеть низкой задержки NextDNS',
      supportsBypass: false,
    }),
    builtin({
      id: 'global_dnssb',
      name: 'DNS.SB',
      provider: 'DNS.SB',
      protocol: 'DoH',
      primaryIp: '185.222.222.222',
      secondaryIp: '45.11.45.11',
      dohUrl: 'https://doh.dns.sb/dns-query',
      dotHost: 'dot.dns.sb',
      category: 'Скоростные',
      country: 'DE',
      tags: ['dnssb', 'privacy', 'no-logs'],
      description: 'Быстрый приватный европейский DoH/DoT DNS.SB',
      supportsBypass: false,
    }),
    builtin({
      id: 'global_dns4eu',
      name: 'DNS4EU Protective',
      provider: 'DNS4EU',
      protocol: 'DoH',
      primaryIp: '86.54.11.1',
      secondaryIp: '86.54.11.100',
      dohUrl: 'https://protective.joindns4.eu/dns-query',
      dotHost: 'protective.joindns4.eu',
      category: 'Магистральные',
      country: 'EU',
      tags: ['dns4eu', 'europe', 'gdpr'],
      description: 'Европейская инициатива DNS4EU с защитой от угроз',
      supportsBypass: false,
    }),
    builtin({
      id: 'global_libredns',
      name: 'LibreDNS',
      provider: 'LibreOps',
      protocol: 'DoH',
      primaryIp: '116.202.176.26',
      dohUrl: 'https://doh.libredns.gr/dns-query',
      dotHost: 'dot.libredns.gr',
      category: 'Антиреклама',
      country: 'DE',
      tags: ['libredns', 'privacy', 'adblock'],
      description: 'Независимый открытый DoH/DoT резолвер LibreDNS',
      supportsBypass: false,
    }),
    builtin({
      id: 'global_uncensoreddns',
      name: 'UncensoredDNS Anycast',
      provider: 'UncensoredDNS',
      protocol: 'DoT',
      primaryIp: '91.239.100.100',
      secondaryIp: '89.233.43.71',
      dotHost: 'anycast.uncensoreddns.org',
      category: 'Магистральные',
      country: 'DK',
      tags: ['uncensoreddns', 'dot', 'denmark'],
      description: 'Датский нецензурируемый DNS с поддержкой DoT',
      supportsBypass: false,
    }),
    builtin({
      id: 'global_yandex',
      name: 'Yandex DNS Basic',
      provider: 'Yandex',
      protocol: 'DoH',
      primaryIp: '77.88.8.8',
      secondaryIp: '77.88.8.1',
      dohUrl: 'https://common.dot.dns.yandex.net/dns-query',
      dotHost: 'common.dot.dns.yandex.net',
      category: 'Магистральные',
      country: 'RU',
      tags: ['yandex', 'ru', 'fast'],
      description: 'Быстрый российский магистральный резолвер для прямого трафика',
      supportsBypass: false,
    }),
    builtin({
      id: 'global_gcore',
      name: 'GCore DNS',
      provider: 'GCore',
      protocol: 'DoH',
      primaryIp: '95.85.95.85',
      secondaryIp: '2.56.220.2',
      dohUrl: 'https://dns.gcorelabs.com/dns-query',
      dotHost: 'dns.gcorelabs.com',
      category: 'Скоростные',
      country: 'LU',
      tags: ['gcore', 'anycast', 'cdn'],
      description: 'Глобальная edge-сеть GCore с низким пингом по СНГ и ЕС',
      supportsBypass: false,
    }),
    builtin({
      id: 'global_common_network',
      name: 'Common Network / Comodo Secure',
      provider: 'Common Network / Comodo',
      protocol: 'UDP',
      primaryIp: '8.26.56.26',
      secondaryIp: '8.20.247.20',
      category: 'Магистральные',
      country: 'US',
      tags: ['comodo', 'common network', 'backbone'],
      description: 'Comodo / Common Network Secure DNS (8.26.56.26 / 8.20.247.20)',
      supportsBypass: false,
    }),
    builtin({
      id: 'global_verisign',
      name: 'Verisign Public DNS',
      provider: 'Verisign',
      protocol: 'UDP',
      primaryIp: '64.6.64.6',
      secondaryIp: '64.6.65.6',
      category: 'Магистральные',
      country: 'US',
      tags: ['verisign', 'backbone', 'stability'],
      description: 'Магистральный резолвер Verisign (64.6.64.6 / 64.6.65.6)',
      supportsBypass: false,
    }),
    builtin({
      id: 'global_level3',
      name: 'Level3 / Lumen DNS',
      provider: 'Level3',
      protocol: 'UDP',
      primaryIp: '4.2.2.1',
      secondaryIp: '4.2.2.2',
      category: 'Магистральные',
      country: 'US',
      tags: ['level3', 'lumen', 'backbone'],
      description: 'Классический магистральный резолвер Level3 (4.2.2.1 / 4.2.2.2)',
      supportsBypass: false,
    })
  );

  return servers;
}

export function parseCatalogTsv(tsvText: string): DnsServer[] {
  const lines = tsvText.split(/\r?\n/).filter((l) => l.trim().length > 0);
  if (lines.length <= 1) return [];

  const result: DnsServer[] = [];
  for (let i = 1; i < lines.length; i++) {
    const cols = lines[i].split('\t');
    if (cols.length < 13) continue;
    const [
      id,
      name,
      provider,
      protoRaw,
      primaryIp,
      secondaryIp,
      dohUrl,
      dotHost,
      catRaw,
      country,
      tagsRaw,
      description,
      supportsBypassRaw,
    ] = cols;

    const protocol: DnsProtocol =
      protoRaw === 'DoH' || protoRaw === 'DoT' || protoRaw === 'SNI443'
        ? protoRaw
        : 'UDP';

    const category: DnsCategory =
      catRaw === 'Smart-DNS' ||
      catRaw === 'Скоростные' ||
      catRaw === 'Антиреклама' ||
      catRaw === 'Игры и Регионы' ||
      catRaw === 'Магистральные'
        ? catRaw
        : 'Скоростные';

    result.push(
      builtin({
        id: id.trim(),
        name: name.trim(),
        provider: provider.trim(),
        protocol,
        primaryIp: primaryIp.trim(),
        secondaryIp: secondaryIp.trim() || undefined,
        dohUrl: dohUrl.trim() || undefined,
        dotHost: dotHost.trim() || undefined,
        category,
        country: country.trim() || 'GLOBAL',
        tags: tagsRaw
          .split(',')
          .map((t) => t.trim())
          .filter(Boolean),
        description: description.trim(),
        supportsBypass: supportsBypassRaw.trim() === 'true',
      })
    );
  }

  return result;
}

export function buildFullBuiltinCatalog(tsvText: string): DnsServer[] {
  const flagships = getFlagshipBuiltinServers();
  const tsvItems = parseCatalogTsv(tsvText);
  const seen = new Set(flagships.map((s) => s.id));
  for (const item of tsvItems) {
    if (!seen.has(item.id)) {
      seen.add(item.id);
      flagships.push(item);
    }
  }
  return flagships;
}
