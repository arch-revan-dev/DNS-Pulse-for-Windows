# Участие в разработке (Contributing Guide)

Спасибо за интерес к **DNS Pulse for Windows**! Этот документ описывает стандарты кода, коммитов и проверки изменений перед отправкой Pull Request.

## Среда разработки

- **Windows WPF клиент (`windows-wpf/`):** .NET 8 SDK (`net8.0-windows`), C# 12 с `Nullable` и `ImplicitUsings`, `CommunityToolkit.Mvvm`, `Microsoft.Data.Sqlite`.
- **Web Studio (`src/`, `server/`):** Node.js 22+, TypeScript, React 19, Vite 8, Express.

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
- **Минимальные привилегии:** не повышайте `requestedExecutionLevel` в [`app.manifest`](windows-wpf/DnsPulse.App/app.manifest) выше `asInvoker` — запрос UAC должен выполняться точечно только при изменении системного DNS/NRPT.
- **Сетевая устойчивость:** внешний сетевой код должен учитывать таймауты, отмену через `CancellationToken` и корректно откатывать временное состояние при сбое.
- **Без мусорных файлов:** не коммитьте локальные `.db`, `.log`, `artifacts/`, `bin/`, `obj/`, `__pycache__/`.

## Обязательные проверки перед Pull Request

### Если менялся код Windows WPF (`.cs`, `.xaml`, `.csproj`)
```powershell
dotnet test windows-wpf/DnsPulse.sln --configuration Release --verbosity normal
```

### Если менялся код Web Studio / общего ядра (`.ts`, `.tsx`, `.json`)
```bash
npm test
npm run lint
npm run build
```

Весь набор проверок автоматически запускается в GitHub Actions ([`.github/workflows/ci.yml`](.github/workflows/ci.yml)).

## Куда сообщать о багах и идеях

- Для ошибок используйте шаблон [Bug Report](.github/ISSUE_TEMPLATE/bug_report.yml).
- Для предложений новых функций — [Feature Request](.github/ISSUE_TEMPLATE/feature_request.yml).
- Об уязвимостях безопасности сообщайте строго в соответствии с [SECURITY.md](SECURITY.md), **не** публикуя детали эксплойта в открытых Issues.
