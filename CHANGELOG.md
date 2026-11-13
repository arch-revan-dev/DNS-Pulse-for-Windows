# Changelog

Все значимые изменения в проекте **DNS Pulse** документируются в этом файле в формате [Keep a Changelog](https://keepachangelog.com/ru/1.1.0/).

## [1.3.0] - 2026-11-13

### Исправлено и переработано
- **Bootstrap DNS и защита от петли `127.0.0.1` (`BootstrapDnsResolver`, `DynamicBypassRegistry`):**
  - Резолв DoH-серверов и онлайн-списков выполняется напрямую через `1.1.1.1 / 8.8.8.8 / 9.9.9.9` (UDP 53 и IP-DoH fallback), минуя системный DNS и проблемные IPv6-маршруты.
  - Встроенный список защищённых AI / Streaming / Gaming-доменов загружается сразу офлайн; сплит-туннель не пропускает нецелевой трафик через Smart-DNS и глушит утечки по `AAAA` / `HTTPS (SVCB)`.
- **4-этапный пробер и системный DNS Windows:**
  - Фолбэк-цепочка `DoH (POST -> GET) -> DoT (853) -> UDP 53 -> TCP 53`, поддержка `smartproxy://`, проверка `/welcome`, `/app`, `alkalimakersuite-pa.clients6.google.com` и детектор геоблока `available-regions` / `sorry/index`.
  - Явный баннер UAC и кнопка перезапуска от имени администратора с автоподключением (`--connect-id` / `--apply-tunnel`), а также отключение утечки IPv6 DNS на активном адаптере.
- **Онлайн-фиды, сканер `/24`, поиск и интерфейс:**
  - Актуализированы фиды (`QuickDNS default_profiles.json`, `dns.malw.link`, `ImMALWARE/dns.malw.link`), добавлена фоновая автосинхронизация при старте и 12 проверенных подсетей `/24` в режиме `AUTO`.
  - Многословный поиск по всем полям узла, живой прогресс-бар тестов, кнопка отмены, обновлённый UI с тёмной и светлой темами («Restrained Graphite»).

## [1.0.0] - 2026-11-13

### Добавлено
- **Windows 10/11 Desktop (.NET 8 WPF MVVM):**
  - Локальный DNS-туннель `127.0.0.1:53` с кэшированием, счётчиком запросов, ротацией серверов и системным треем.
  - Автоматический бэкап и восстановление исходных DNS сетевых адаптеров (`restore_network_state.json`) и поддержка Windows NRPT split-routing.
  - Вкладки `Тестер`, `Каталог` и `Конфиги`, фильтры, сортировка, переключение светлой/тёмной темы «Restrained Graphite», диалог `Подбор` (`/24` сканер и синхронизация онлайн-фидов).
  - Встроенный в сборку ресурс `dns_catalog_1000.tsv` для корректной работы single-file `.exe`.
  - Скрипт установщика Windows x64 (`windows-wpf/installer/DnsPulse.iss`).
- **4-этапный движок диагностики (без ложных срабатываний):**
  - Проверка bogon/loopback IP, Anti-Direct-IP фильтр прямых CDN/Google/OpenAI подсетей, проверка companion API-доменов и реальный TLS SNI + HTTP `GET /` на порту `443` с детектом `/docs/available-regions`.
- **База 1050+ DNS-серверов (Zero-Token / Zero-Default-Favorites):**
  - Кластер Bezmezhau (`dns.bezmezhau.com`, `gemini1..20.bezmezhau.com`), MagicDNS, GeoHide (DoH + 8 узлов SNI 443), Malw.link, Comss.one, Xbox-DNS, AstraCat, Zapret.moe, Shecan, 403.online, Begzar, Electro, Radar Game, Control D, Cloudflare, Google, Quad9, OpenDNS, AdGuard, Mullvad, NextDNS, DNS.SB, DNS4EU, LibreDNS, UncensoredDNS, Yandex, GCore, Common Network/Comodo, Verisign, Level3 + 1020 каталожных серверов.
- **Веб-студия диагностики и CI/CD:**
  - Полный стек Express + `node:sqlite` + React + Vite + Tailwind CSS v4.
  - Экспорт готового open-source пакета `/api/export/windows-wpf.zip`.
  - GitHub Actions CI (`ci.yml`) и Release (`release.yml`) с генерацией `SHA256SUMS.txt`.

### Исправлено
- Очистка входящих EDNS0 `OPT`-записей (`ARCOUNT = 0`) в локальном UDP DNS-туннеле (TypeScript и C#), устраняющая некорректные ответы при запросах `nslookup` и `dnscache`.
- Использование `GET /` вместо `HEAD /` при 4-этапной TLS/SNI-проверке на порту `443`, чтобы избежать ложных отказов `403/405` от прокси.
- Безопасный разбор некорректных DoH URL в plain-text импортёре без исключений.
- Корректная группировка скобок при определении JSON-источников в модуле Discovery.
