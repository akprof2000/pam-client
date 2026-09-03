# pam-client

Go-клиент и консольная утилита для получения секретов из PAM по протоколу
**AAPM REST API** (Application-to-Application Password Management, Kron PAM).

Приложение обращается к серверу PAM со своим AAPM-токеном и получает секрет
по пути записи. В зависимости от типа записи в ответе приходит логин с паролем,
произвольные данные (например токен), SSL-сертификат или SSH-ключ — библиотека
распознаёт тип сама и раскладывает значения по полям.

- Библиотека: `github.com/akprof2000/pam-client/pam`
- Утилита: `cmd/pamget`
- Имитация сервера для тестов и отладки: `cmd/fakepam`, пакет `pam/mockpam`

Зависимостей, кроме стандартной библиотеки Go, нет.

---

## Содержание

1. [Быстрый старт](#быстрый-старт)
2. [Установка](#установка)
3. [Утилита pamget](#утилита-pamget)
4. [Библиотека](#библиотека)
5. [Настройка TLS](#настройка-tls)
6. [Типы записей](#типы-записей)
7. [Обработка ошибок и повторы](#обработка-ошибок-и-повторы)
8. [Локальный стенд без реального PAM](#локальный-стенд-без-реального-pam)
9. [Сборка релизов](#сборка-релизов)
10. [Тесты](#тесты)
11. [Как это устроено внутри](#как-это-устроено-внутри)
12. [Безопасность](#безопасность)

---

## Быстрый старт

```bash
export PAM_SERVER=https://pam.example.com
export PAM_TOKEN=00000000-0000-0000-0000-000000000000

pamget -secret /Группа/Подгруппа/имя_записи
```

```
  СЕКРЕТ  /Группа/Подгруппа/имя_записи
  тип     логин и пароль

  логин   app_user
  пароль  ••••••••

  тип записи: STATIC   группа: /Группа/Подгруппа   изменён: 2026-09-03 12:31:07
```

Для скриптов — вывод без оформления:

```bash
PASSWORD=$(pamget -secret /Группа/Подгруппа/имя_записи -raw)
```

---

## Установка

Готовые сборки — на вкладке Releases: `.zip` для Windows и `.tar.gz` для
Linux (CentOS/RHEL 7+, Debian, Ubuntu). Бинарники статические, CGO не
используется — установка сводится к распаковке архива.

```bash
tar -xzf pam-client_v1.0.0_linux_amd64.tar.gz
cd pam-client_v1.0.0_linux_amd64
./pamget -version
```

Сборка из исходников (нужен Go 1.21+):

```bash
go install github.com/akprof2000/pam-client/cmd/pamget@latest
```

Использование как библиотеки:

```bash
go get github.com/akprof2000/pam-client
```

---

## Утилита pamget

### Основные флаги

| Флаг | Значение по умолчанию | Назначение |
|---|---|---|
| `-server` | `$PAM_SERVER` | адрес сервера PAM |
| `-token` | `$PAM_TOKEN` | токен AAPM-аккаунта |
| `-secret` | — | полный путь записи: `/группа/имя` |
| `-list` | `false` | показать записи, доступные токену |
| `-field` | — | вывести одно поле: `username`, `password`, `data`, `ssl-certificate`, `ssh-key`, `passphrase` |
| `-raw` | `false` | только значение секрета, без оформления |
| `-json` | `false` | весь ответ (секрет + метаданные) в JSON |
| `-insecure` | `false` | не проверять сертификат сервера |
| `-ca` | — | файл доверенного корневого сертификата (PEM) |
| `-expire` | `0` | срок жизни выданного пароля в минутах |
| `-change-required` | `false` | требовать смену пароля после выдачи |
| `-comment` | — | комментарий в журнал аудита PAM |
| `-timeout` | `30s` | таймаут одного запроса |
| `-retries` | `2` | число повторов при сетевых сбоях и ответах 429/5xx |
| `-version` | — | показать версию |

### Форматы вывода

По умолчанию вывод рассчитан на человека: заголовок, поля с понятными
названиями, метаданные записи. Многострочные значения (сертификаты, ключи)
печатаются блоком. Цвет включается только когда вывод идёт в терминал;
при перенаправлении в файл или конвейер, а также при `NO_COLOR=1`,
escape-последовательности не выводятся.

Три режима для автоматизации:

```bash
pamget -secret /группа/имя -raw                 # только значение
pamget -secret /группа/имя -field username      # одно поле
pamget -secret /группа/имя -json                # весь ответ в JSON
```

### Коды возврата

`0` — успех, `1` — любая ошибка. Текст ошибки уходит в stderr, поэтому
`$(pamget ... -raw)` не «поймает» его вместе со значением.

---

## Библиотека

```go
package main

import (
	"context"
	"fmt"
	"log"
	"os"

	"github.com/akprof2000/pam-client/pam"
)

func main() {
	// Адрес можно передать явно; "" означает значение из PAM_SERVER.
	client, err := pam.New("https://pam.example.com", os.Getenv("PAM_TOKEN"))
	if err != nil {
		log.Fatal(err)
	}

	secret, err := client.Get(context.Background(), "/Группа/Подгруппа/имя_записи")
	if err != nil {
		log.Fatal(err)
	}

	switch secret.Kind {
	case pam.KindUserCredentials:
		fmt.Println(secret.Username, secret.Password)
	case pam.KindSecretData:
		fmt.Println(secret.Data)
	case pam.KindSSLCertificate:
		fmt.Println(secret.Certificate)
	case pam.KindSSHKey:
		fmt.Println(secret.PrivateKey, secret.Passphrase)
	}
}
```

### Опции клиента

```go
client, err := pam.New(server, token,
	pam.WithCACertFile("/etc/pki/tls/certs/ca-bundle.crt"), // доверенный корневой сертификат
	pam.WithClientCert("client.crt", "client.key"),         // взаимный TLS
	pam.WithInsecureSkipVerify(false),                      // проверка включена по умолчанию
	pam.WithTimeout(5*time.Second),                         // таймаут одного запроса
	pam.WithRetry(2, 200*time.Millisecond),                 // повторы при сбоях
	pam.WithComment("сервис биллинга, задача BILL-42"),     // комментарий в аудит
	pam.WithPasswordExpiration(30),                         // срок жизни пароля, минуты
	pam.WithPath("/sc-aapm-ui/rest/aapm/password"),         // путь эндпоинта
	pam.WithHTTPClient(myClient),                           // свой http.Client
	pam.WithUserAgent("billing/1.4"),
)
```

### Расширенный запрос

```go
secret, err := client.GetSecret(ctx, pam.Request{
	AccountPath:                "/Группа/Подгруппа",
	AccountName:                "имя_записи",
	Comment:                    "задача BILL-42",
	PasswordExpirationInMinute: 30,    // 0 — значение клиента, отрицательное — не передавать
	PasswordChangeRequired:     false,
})
```

### Список доступных записей

```go
accounts, err := client.ListAccounts(ctx)
for _, a := range accounts {
	fmt.Println(a.FullPath(), a.SecretType)
}
```

### Адрес сервера

Адрес не зашит в код. Порядок разрешения:

1. аргумент `pam.New(server, ...)` / флаг `-server`;
2. переменная окружения `PAM_SERVER`;
3. значение, заданное при сборке:
   `-ldflags "-X github.com/akprof2000/pam-client/pam.DefaultServer=https://pam.example.com"`.

Если адрес не задан ни одним способом, `New` возвращает ошибку.

---

## Настройка TLS

Проверка сертификата сервера **включена по умолчанию** и использует системное
хранилище доверенных корней. Минимальная версия протокола — TLS 1.2.

| Ситуация | Решение |
|---|---|
| Сертификат от публичного УЦ | ничего настраивать не нужно |
| Корпоративный УЦ | `-ca /путь/к/ca.pem` или `pam.WithCACertFile(...)` |
| Сервер требует клиентский сертификат | `pam.WithClientCert(cert, key)` |
| Тестовый стенд с самоподписанным сертификатом | `-insecure` / `pam.WithInsecureSkipVerify(true)` |

`-insecure` полностью отключает проверку подлинности сервера: в этом режиме
секрет может быть выдан перехватчику. Использовать только на стендах.

---

## Типы записей

Тип определяется по набору ключей в объекте `secret` ответа — отдельного поля
с типом в API нет.

| Ключи в ответе | `Kind` | Заполняемые поля | Что вернёт `String()` |
|---|---|---|---|
| `username`, `password` | `KindUserCredentials` | `Username`, `Password` | пароль |
| `data` | `KindSecretData` | `Data` | данные |
| `ssl-certificate` | `KindSSLCertificate` | `Certificate` | сертификат |
| `ssh-key`, `passphrase`, `username` | `KindSSHKey` | `PrivateKey`, `Passphrase`, `Username` | приватный ключ |
| прочее | `KindUnknown` | только `Raw` | пустая строка |

Исходный объект всегда доступен в `secret.Raw` (`map[string]string`),
метаданные записи — в `secret.Properties` (`SecretName`, `SecretType`,
`GroupFullPath`, `OwnerEID`, `CreatedAt`, `UpdatedAt` и другие).
Времена приходят в миллисекундах Unix; тип `EpochMS` даёт метод `Time()`.

Значения секрета остаются строками ровно в том виде, в каком их прислал сервер:
пароль `12345` не превращается в число, а секрет, содержащий JSON, — в структуру.

---

## Обработка ошибок и повторы

Ошибка HTTP приходит типом `*pam.HTTPError` с кодом и телом ответа:

```go
var httpErr *pam.HTTPError
if errors.As(err, &httpErr) && httpErr.StatusCode == http.StatusUnauthorized {
	// неверный или отозванный токен
}
```

Повторы (по умолчанию 2, пауза удваивается начиная с 200 мс) выполняются при
сетевых сбоях и ответах `429`, `500`, `502`, `503`, `504`. Не повторяются:
`401`, `403`, `404`, прочие `4xx`, ошибки проверки сертификата и отменённый
контекст.

Токен передаётся в query-строке, поэтому библиотека вырезает его из текста
сетевых ошибок — в логи приложения он не попадёт.

---

## Локальный стенд без реального PAM

`cmd/fakepam` поднимает имитацию AAPM REST API: те же эндпоинты, те же формы
ответов, самоподписанный TLS-сертификат.

```bash
fakepam -addr 127.0.0.1:8443 -cert-out ./fakepam.pem
```

```bash
pamget -server https://127.0.0.1:8443 \
       -token 00000000-0000-0000-0000-000000000001 \
       -ca ./fakepam.pem \
       -secret /Example/Common/Test/test_accounts/static_user_credentials
```

Готовые сценарии проверки всех четырёх типов записей и поведения TLS:

```bash
./scripts/demo.sh
```

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\demo.ps1
```

Скрипт сам поднимает стенд, прогоняет запросы и останавливает сервер;
реальный PAM и настоящий токен для этого не нужны.

Тот же обработчик доступен как библиотека `pam/mockpam` — его удобно
подключать в тестах своего приложения:

```go
h := mockpam.NewHandler("тестовый-токен", mockpam.DemoAccounts()...)
srv := mockpam.NewServer(h)
defer srv.Close()

client, _ := pam.New(srv.URL, "тестовый-токен")
```

---

## Сборка релизов

### Версионирование

Проект использует семантическое версионирование: `vМАЖОРНАЯ.МИНОРНАЯ.ПАТЧ`.
Версия задаётся git-тегом и попадает в бинарники на этапе сборки
(`-ldflags "-X main.version=..."`), поэтому её всегда видно:

```bash
pamget -version
```

История изменений — в [CHANGELOG.md](CHANGELOG.md).

### Автоматическая сборка в GitHub Actions

Пуш тега вида `v*` запускает workflow `.github/workflows/release.yml`:
он прогоняет тесты, кросс-компилирует бинарники, собирает архивы
и публикует их в GitHub Releases вместе с `SHA256SUMS`.

```bash
git tag -a v1.0.1 -m "исправление разбора списка записей"
git push origin v1.0.1
```

Workflow можно запустить и вручную (Actions → Release → Run workflow),
указав версию в поле ввода.

Каждый push и pull request дополнительно проходит `.github/workflows/ci.yml`:
`gofmt`, `go vet`, тесты на Linux и Windows, детектор гонок, короткий фаззинг
и демонстрационный сценарий.

### Локальная сборка

```bash
./scripts/release.sh v1.0.0
```

Скрипт прогоняет `go vet` и тесты, кросс-компилирует обе команды и складывает
в `dist/`:

- `pam-client_<версия>_windows_amd64.zip`
- `pam-client_<версия>_linux_amd64.tar.gz`
- `pam-client_<версия>_linux_arm64.tar.gz`
- `SHA256SUMS`

В каждый архив попадают `pamget`, `fakepam`, README, лицензия и демо-скрипт
для соответствующей ОС. Сборка идёт с `CGO_ENABLED=0`, поэтому бинарники
не зависят от версии glibc и запускаются в том числе на CentOS 7.

---

## Тесты

```bash
go test ./...
```

```bash
go test -cover ./...
```

```bash
go test ./pam/ -run xxx -fuzz FuzzParsePath -fuzztime 30s
```

Покрытие: около 96% по библиотеке и 97% по имитации сервера. Проверяются
все четыре типа записей, состав параметров запроса, значения по умолчанию,
разбор метаданных, повреждённые ответы, коды 401/403/404/429/5xx, повторы
и их отсутствие там, где повтор не нужен, три режима проверки TLS,
таймауты и отмена контекста, параллельное использование клиента и
отсутствие токена в текстах ошибок.

---

## Как это устроено внутри

Один запрос к API — обычный `GET` с параметрами в query-строке:

```
GET {server}/sc-aapm-ui/rest/aapm/password
    ?token=<токен>
    &sapmAccountPath=<путь группы>
    &sapmAccountName=<имя записи>
    &responseType=JSON
    &passwordChangeRequired=<true|false>
    &passwordExpirationInMinute=<минуты>
    &comment=<комментарий>
```

Ответ:

```json
{
  "secret": { "username": "...", "password": "..." },
  "properties": { "secretName": "...", "secretType": "STATIC" }
}
```

Структура репозитория:

```
pam/            библиотека: клиент, разбор ответа
pam/mockpam/    имитация сервера (используется в тестах и cmd/fakepam)
cmd/pamget/     консольная утилита
cmd/fakepam/    запускаемый тестовый сервер
scripts/        демо-сценарии и сборка релизов
```

---

## Безопасность

- Токен передавайте через переменную окружения, а не аргументом командной
  строки: аргументы видны в списке процессов и остаются в истории оболочки.
- Не отключайте проверку TLS на рабочих контурах.
- Секрет печатается в stdout — не перенаправляйте вывод в файлы и логи,
  которые хранятся долго.
- Каждая выдача секрета фиксируется в журнале аудита PAM; заполняйте
  `-comment` осмысленно, это упрощает разбор инцидентов.

---

## Лицензия

MIT — см. [LICENSE](LICENSE).
