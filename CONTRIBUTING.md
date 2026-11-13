# Участие в разработке (Contributing Guide)

Спасибо за интерес к **DNS Pulse for Windows**! Этот документ описывает стандарты кода, коммитов и проверки изменений перед отправкой Pull Request.

## Среда разработки

- **PulseCore & Windows Desktop / Service (`src/`, `tests/`, `DnsPulse.sln`):** .NET 9 SDK (`net9.0` для `DnsPulse.Core` и `DnsPulse.Engine`; `net9.0-windows10.0.19041.0` для `DnsPulse.Platform.Windows`, `DnsPulse.Service` и `DnsPulse.App`), C# 13 (`LangVersion=latest`) с `Nullable`, `ImplicitUsings`, `TreatWarningsAsErrors=true`, `AnalysisLevel=latest-all`, `WPF-UI` 4.3, `CommunityToolkit.Mvvm`, `Microsoft.Data.Sqlite`, `Serilog`.
- **Web Studio (`tools/web-studio/`, опционально):** Node.js 22+, TypeScript, React 19, Vite 8, Express.

## Процесс работы с ветками и коммитами

1. Создавайте тематическую ветку от актуальной `main`:
   - `feat/<краткое-описание>` — новая функциональность
   - `fix/<краткое-описание>` — исправление ошибки
   - `docs/<краткое-описание>` — документация
   - `refactor/<краткое-описание>` — рефакторинг без изменения поведения
2. Используйте формат **[Conventional Commits](https://www.conventionalcommits.org/)**:
   - `feat(settings): add custom DNS timeout slider`
   - `fix(prober): handle empty EDNS0 OPT records in UDP tunnel`
   - `docs(readme): update release verification steps`
   - `ci(release): sign checksum manifest`

## Требования к качеству и безопасности

- **Никаких секретов и личных токенов:** категорически запрещено добавлять в каталог серверов, тесты или примеры персональные DoH/NextDNS/ControlD URL-токены, API-ключи или пароли.
- **Минимальные привилегии:** не повышайте `requestedExecutionLevel` в [`app.manifest`](src/DnsPulse.App/app.manifest) выше `asInvoker` — привилегированный системный перехват выполняется через службу Windows `DnsPulseService` / точечный UAC-запрос, а unprivileged-режим использует локальный `LocalProxyPacOnly`.
- **Сетевая устойчивость:** внешний сетевой код должен учитывать таймауты, отмену через `CancellationToken` и корректно откатывать временное состояние при сбое.
- **Без мусорных файлов:** не коммитьте локальные `.db`, `.log`, `artifacts/`, `bin/`, `obj/`, `__pycache__/`.

## Обязательные проверки перед Pull Request

### Если менялся код .NET 9 (`.cs`, `.xaml`, `.csproj`, `.props`)
```powershell
dotnet build DnsPulse.sln -c Release
dotnet test DnsPulse.sln -c Release --no-build --verbosity normal
dotnet format DnsPulse.sln --verify-no-changes
```

### Если менялся код Web Studio (`tools/web-studio/`)
```bash
cd tools/web-studio
npm test
npm run lint
npm run build
```

Весь набор проверок автоматически запускается в GitHub Actions ([`.github/workflows/ci.yml`](.github/workflows/ci.yml)).

## Куда сообщать о багах и идеях

- Для ошибок используйте шаблон [Bug Report](.github/ISSUE_TEMPLATE/bug_report.yml).
- Для предложений новых функций — [Feature Request](.github/ISSUE_TEMPLATE/feature_request.yml).
- Об уязвимостях безопасности сообщайте строго в соответствии с [SECURITY.md](SECURITY.md), **не** публикуя детали эксплойта в открытых Issues.
