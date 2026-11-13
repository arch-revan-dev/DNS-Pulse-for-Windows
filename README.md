# DNS Pulse

**DNS Pulse** — open-source инструмент для тестирования, автоподбора, управления базами DNS-серверов (`UDP 53`, `DoH RFC 8484`, `DoT 853`, `SNI-Proxy 443`) и точечного обхода региональных ограничений (Gemini, Google AI Studio, ChatGPT, Claude, Spotify, Xbox Live и др.) без полноценного VPN.

Проект включает:
1. **Десктопный клиент для Windows 10 / 11** (`windows-wpf/`, C# .NET 8 + WPF MVVM, SQLite, локальный DNS-туннель `127.0.0.1:53`, NRPT split-routing, трей и ротация).
2. **Веб-студию диагностики** (React + TypeScript + Express + `node:sqlite`), выполняющую реальные UDP/DoH/DoT/TLS-SNI замеры и сборку `.zip`-архива Windows-проекта.

---

## Ключевые возможности

- **4-этапный движок без ложных срабатываний:**
  1. Проверка DNS-ответа на bogon/loopback (`0.0.0.0`, `127.0.0.1`).
  2. **Anti-Direct-IP фильтр** — отклоняет обычные резолверы (например, `1.1.1.1` / `8.8.8.8`), которые просто быстро отдают прямые подсети Google/OpenAI без проксирования.
  3. **Проверка companion API-доменов** (`alkalimakersuite-pa.clients6.google.com`, `generativelanguage.googleapis.com` и др.).
  4. **Реальный TLS SNI + HTTP GET на порту 443** с детектом геоблока (`/docs/available-regions`, `403`, `451`).
- **Локальный DNS-туннель (`127.0.0.1:53`) и Split-Routing:**
  - Прозрачная работа DoH/DoT/SNI-Proxy даже на Windows 10.
  - Автоматический бэкап и гарантированное восстановление исходных DNS адаптера (`restore_network_state.json`) при выходе или аварийном перезапуске.
  - Резолв через Smart-DNS только для доменов обхода; остальной трафик идёт напрямую.
- **База 1050+ встроенных серверов без токенов:**
  - Встроенный TSV-каталог (`assets/dns_catalog_1000.tsv`) + кластеры Bezmezhau (`dns.bezmezhau.com`, `gemini1..20.bezmezhau.com`), MagicDNS, GeoHide, Malw.link, Comss.one, Xbox-DNS, AstraCat, Zapret.moe, Shecan, 403.online, Cloudflare, Google, Quad9 и др.
  - **Политика open-source:** ноль персональных подписок/токенов и ноль предустановленных «избранных».
- **Подбор, сканер `/24` и синхронизация:**
  - Параллельный сканер подсетей и портов `53` / `443`.
  - Синхронизация динамических списков (`dns.malw.link/hosts`, `QuickDNS`) с офлайн-кэшем.
  - Импорт/экспорт `JSON`, `CSV` и plain-text списков + локальный JSON-сейф пользовательских адресов.

---

## Структура репозитория

```text
├── assets/
│   └── dns_catalog_1000.tsv          # Каталог 1000+ публичных и Smart-DNS серверов
├── server/                           # Express API + SQLite + реальные DNS/TLS-пробы
├── src/                              # React + TypeScript UI и чистая логика (src/core/)
├── windows-wpf/                      # Windows 10/11 C# .NET 8 WPF MVVM проект
│   ├── DnsPulse.App/                 # Приложение (Views, ViewModels, NetworkEngine, Data, Services)
│   ├── DnsPulse.Tests/               # xUnit тесты
│   └── installer/DnsPulse.iss        # Скрипт инсталлятора Inno Setup (x64)
├── .github/workflows/
│   ├── ci.yml                        # Автоматические тесты Web + .NET 8
│   └── release.yml                   # Сборка Windows x64 .exe, portable .zip, setup .exe и SHA256
├── CHANGELOG.md
└── LICENSE
```

---

## Сборка и запуск

### Windows Desktop (.NET 8 WPF)
Требуется Windows 10/11 и [.NET 8 SDK](https://dotnet.microsoft.com/download/dotnet/8.0).

```powershell
# Восстановление пакетов и запуск xUnit-тестов
dotnet test windows-wpf/DnsPulse.sln --configuration Release

# Запуск WPF-приложения
dotnet run --project windows-wpf/DnsPulse.App/DnsPulse.App.csproj

# Сборка автономного portable .exe (без требования установленного .NET на целевом ПК)
dotnet publish windows-wpf/DnsPulse.App/DnsPulse.App.csproj `
  -c Release -r win-x64 --self-contained true `
  -p:PublishSingleFile=true -p:IncludeNativeLibrariesForSelfExtract=true `
  -o artifacts/win-x64
```

### Веб-студия диагностики (Node.js 22+)

```bash
npm install
npx tsx --test src/core/dnsEngine.test.ts
npm run lint
npm run build
npm run dev
```

---

## Выпуск релиза (GitHub Releases)

Чтобы автоматически собрать `DnsPulse.exe`, `DNS-Pulse-win-x64-portable.zip`, инсталлятор `DNS-Pulse-win-x64-setup.exe` и `SHA256SUMS.txt`:

```bash
git tag v1.0.0
git push origin v1.0.0
```

Workflow `.github/workflows/release.yml` прогонит тесты, соберёт релизные артефакты на `windows-latest` и опубликует релиз в GitHub.

---

## Лицензия

Распространяется по лицензии [MIT](LICENSE).
