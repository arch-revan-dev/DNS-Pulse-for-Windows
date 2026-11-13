<div align="center">

<img src="src/DnsPulse.App/Assets/app.ico" alt="DNS Pulse Icon" width="76" height="76" />

# DNS Pulse v2.0 (PulseCore) для Windows

**Открытый локальный роутер шифрованного DNS, 4-зонный движок разделения имён, 6-уровневый диагност доступности и бездрайверный TLS-Split PAC-сайдар для Windows 10/11.**

**[English Version (README.md)](README.md)**

[![Release](https://img.shields.io/github/v/release/arch-revan-dev/DNS-Pulse-for-Windows?style=for-the-badge&logo=github&color=10b981)](https://github.com/arch-revan-dev/DNS-Pulse-for-Windows/releases/latest)
[![CI](https://img.shields.io/github/actions/workflow/status/arch-revan-dev/DNS-Pulse-for-Windows/ci.yml?branch=main&style=for-the-badge&logo=githubactions&label=CI)](https://github.com/arch-revan-dev/DNS-Pulse-for-Windows/actions/workflows/ci.yml)
[![Security](https://img.shields.io/github/actions/workflow/status/arch-revan-dev/DNS-Pulse-for-Windows/security.yml?branch=main&style=for-the-badge&logo=githubactions&label=Security)](https://github.com/arch-revan-dev/DNS-Pulse-for-Windows/actions/workflows/security.yml)
[![Platform](https://img.shields.io/badge/Windows-10%20%2F%2011%20(x64%20%7C%20arm64)-0078D6?style=for-the-badge&logo=windows11)](https://github.com/arch-revan-dev/DNS-Pulse-for-Windows/releases)
[![.NET](https://img.shields.io/badge/.NET-9.0%20PulseCore-512BD4?style=for-the-badge&logo=dotnet)](https://dotnet.microsoft.com/)
[![License](https://img.shields.io/github/license/arch-revan-dev/DNS-Pulse-for-Windows?style=for-the-badge&color=64748b)](LICENSE)

[Возможности](#-матрица-возможностей-pulsecore-v20) • [Быстрый старт](#-быстрый-старт) • [Архитектура](#-обзор-архитектуры) • [6-уровневая диагностика](docs/DNS_DIAGNOSTICS.md) • [Модель угроз](docs/THREAT_MODEL.md) • [Приватность](docs/PRIVACY.md) • [Свой VPS](docs/SELF_HOSTED_VPS.md) • [Безопасность](SECURITY.md)

</div>

---

## Зачем нужен DNS Pulse?

Обычные DNS-тестеры измеряют лишь ICMP ping до `1.1.1.1` или `8.8.8.8`. Это ничего не говорит о том, подменяет ли провайдер незашифрованные ответы, сбрасывает ли DPI TLS-соединение по заголовку SNI, блокирует ли порты DoH/DoT или возвращает ли Smart-DNS прямой IP CDN с немедленной ошибкой региона `403`/`451`.

**DNS Pulse v2.0 (PulseCore)** — это детерминированный локальный маршрутизатор на `.NET 9` с нулевой телеметрией: **4-зонный Split-Namespace движок**, **6-уровневый диагност доступности**, **бездрайверный TLS-Split PAC-сайдар** (безопасный для античитов), проверка подлинности **Ed25519** и **Dead-Man's Switch**, гарантирующий сохранность сетевых настроек Windows при любом сбое.

---

## Матрица возможностей PulseCore v2.0

| Компонент | Реализация в PulseCore v2.0 |
|---|---|
| **Шифрованные протоколы DNS** | `DoH` (HTTP/2 POST/GET), `DoH3` (HTTP/3), `DoT` (RFC 7858), `DoQ` (RFC 9250 QUIC), `DNSCrypt v2`, `Anonymized DNSCrypt`, `ODoH` (RFC 9230 HPKE), `DDR` (`_dns.resolver.arpa`), штампы `sdns://` |
| **4-зонный Split-Namespace** | Lock-free префиксные деревья (`DomainRadixTrie`, `CidrRadixTrie`) со строгим приоритетом: `Zone 1 Local` > `Security Pinning` > `Zone 2 Block/Allow` > `Zone 3 Geo-Unlock` > `Zone 4 Encrypted Trusted` |
| **ECH и записи HTTPS/SVCB** | Сохраняет ключ `ECH` в Zone 4 для приватности; очищает ECH/IPv6-подсказки в Zone 3 (`HttpsSvcbRouteRewriter`) для корректной работы Smart-DNS и SNI-Proxy по IPv4 |
| **6-уровневый диагност** | Здоровье хоста (Port 53 / DoH браузеров) → Замер RTT (`p50`/`p95`/джиттер) → Целостность ответа → Fail-closed X.509/SAN/ALPN → HTTPS Geo-проба + Companion API → Точный вердикт и решение |
| **Бездрайверный TLS-Split PAC** | `AutoPacServer` (`/proxy.pac`) + `TlsFragmentationProxyServer` (HTTP `CONNECT`, HTTP, SOCKS5): фрагментация `ClientHello` по границе SNI с защитой от SSRF, без ядерных драйверов |
| **Аварийное восстановление** | Атомарный журнал `NetworkSnapshotJournal` с SHA-256, сторожевой таймер службы `DnsPulseService` (10 с Dead-Man's Switch), ярлык **Emergency Network Restore** (`--restore-network`) и откат при удалении |
| **Генератор своего VPS** | `SelfHostedVpsGenerator` создаёт защищённый стек (`docker-compose.yml`, `nginx.conf` с IP-allowlist и 256-битным Bearer-токеном, `Corefile`/`AdGuardHome.yaml`, скрипт UFW и штамп `sdns://`) |
| **Нулевая телеметрия** | Кольцевой буфер только в RAM (`QueryTelemetryBuffer`, 2000 записей), `ZeroDiskQueryLogging = true` по умолчанию, редактируемый экспорт диагностического ZIP |

---

## Гарантии безопасности

- **Разделение привилегий и Named Pipe ACL:** интерфейс `DnsPulse.App` работает с правами обычного пользователя (`asInvoker`). Привилегированные изменения адаптеров, NRPT и брандмауэра изолированы в службе `DnsPulse.Service.exe` за каналом `\\.\pipe\DnsPulse.Control.v1` с DACL только для `SYSTEM`, `Administrators` и текущего интерактивного пользователя.
- **Инвариант нулевого доверия Zone 4:** серверы `Tier4ExperimentalLab`, незашифрованный `UDP`/`TCP` и `SniProxy` строго не допускаются в Zone 4 и для критичных доменов (`ocsp.*`, `crl.*`, обновления ОС, банки, центры сертификации, авторизация).
- **Совместимость с античитами:** стандартные режимы (`AdapterDns`, `SplitNrpt`, `LocalProxyPacOnly`) и TLS-Split PAC работают полностью в пользовательском режиме. Опциональный `WfpDivertPlugin` через `AntiCheatGuard` автоматически блокирует запуск при обнаружении Riot Vanguard, Easy Anti-Cheat, FACEIT или BattlEye.
- **Криптографическая проверка:** RFC 8032 `Ed25519Verifier` и константный `SHA-256` для обновлений и подписанных фидов (`RequireSigned`).

---

## Быстрый старт

1. Скачайте актуальный релиз в **[GitHub Releases](https://github.com/arch-revan-dev/DNS-Pulse-for-Windows/releases/latest)**:
   - **`DNS-Pulse-win-x64-setup.exe`** (или `win-arm64`) — установщик Inno Setup с опциональной службой Windows и ярлыком экстренного сброса сети.
   - **`DNS-Pulse-win-x64-portable.zip`** — портативная сборка.
2. *(Опционально)* Проверьте хеш по **`SHA256SUMS.txt`**:
   ```powershell
   Get-FileHash .\DNS-Pulse-win-x64-setup.exe -Algorithm SHA256
   ```
3. Запустите **DNS Pulse**, выполните 6-уровневую диагностику или нажмите автоподбор рабочего `Tier1EncryptedTrusted` узла и подключитесь.
4. Для мгновенного отката сетевых настроек в любой ситуации используйте **Меню Пуск → DNS Pulse → Экстренное восстановление сети** (`DnsPulse.exe --restore-network`).

---

## Обзор архитектуры

```text
DNS-Pulse-for-Windows/
├── .github/workflows/           # ci.yml, release.yml, security.yml (CodeQL + Scorecard)
├── assets/dns_catalog_1000.tsv  # Встроенный каталог серверов и флагманских узлов
├── docs/                        # ARCHITECTURE, THREAT_MODEL, PRIVACY, DNS_DIAGNOSTICS, SELF_HOSTED_VPS
├── installer/                   # Inno Setup (DnsPulse.iss), WiX v4 (wix/Package.wxs), WinGet манифесты
├── src/
│   ├── DnsPulse.Core/           # Модели net9.0, кодек RFC, 4-зонный роутер, штампы sdns://, Ed25519
│   ├── DnsPulse.Engine/         # Транспорты, bootstrap, кэш, TLS-Split сайдар, 6-уровневый диагност, VPS
│   ├── DnsPulse.Platform.Windows/ # Win32 NIC/NRPT/COM firewall, журнал снимков, ACL Pipe, апдейтер
│   ├── DnsPulse.Service/        # Служба Windows и Dead-Man's Switch (10 с)
│   └── DnsPulse.App/            # Десктопное приложение .NET 9 WPF-UI 4.3.0 (asInvoker)
├── tests/                       # Модульные и интеграционные тесты xUnit
└── tools/web-studio/            # Опциональная веб-студия диагностики (TypeScript + React)
```

Подробная документация (на английском языке):
- [Архитектура PulseCore](docs/ARCHITECTURE.md)
- [Модель угроз](docs/THREAT_MODEL.md)
- [Приватность и отсутствие телеметрии](docs/PRIVACY.md)
- [Руководство по 6-уровневой диагностике](docs/DNS_DIAGNOSTICS.md)
- [Развёртывание собственного защищённого VPS](docs/SELF_HOSTED_VPS.md)

---

## Сборка из исходников

### Требования
- [.NET 9 SDK](https://dotnet.microsoft.com/download/dotnet/9.0) на Windows 10/11 (`10.0.19041.0`+)
- Опционально: [Inno Setup 6](https://jrsoftware.org/isinfo.php) или [WiX Toolset v4](https://wixtoolset.org/)

### Команды сборки и тестов
```powershell
dotnet restore DnsPulse.sln
dotnet test DnsPulse.sln --configuration Release --no-restore

# Сборка self-contained desktop-приложения (win-x64 или win-arm64)
dotnet publish src/DnsPulse.App/DnsPulse.App.csproj `
  -c Release -r win-x64 --self-contained true `
  -p:PublishSingleFile=true -p:IncludeNativeLibrariesForSelfExtract=true `
  -o artifacts/win-x64

# Сборка службы Windows рядом с основным исполняемым файлом
dotnet publish src/DnsPulse.Service/DnsPulse.Service.csproj `
  -c Release -r win-x64 --self-contained true `
  -p:PublishSingleFile=true -o artifacts/win-x64

# Сборка установщика Inno Setup
iscc.exe /DArch=win-x64 /DAppVersion=2.0.0 installer/DnsPulse.iss
```

---

## Участие в разработке и лицензия

Будем рады Pull Request и сообщениям об ошибках! Ознакомьтесь с [CONTRIBUTING.md](CONTRIBUTING.md) и [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md).

Проект распространяется под лицензией [MIT License](LICENSE). © 2026 DNS Pulse Open Source Contributors.
