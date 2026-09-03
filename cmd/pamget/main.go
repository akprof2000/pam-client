// Команда pamget — консольная утилита к пакету pam: получает секрет из PAM
// (AAPM REST API) и печатает его в stdout.
//
// Простейший вызов:
//
//	pamget -server https://pam.example.com -token <токен> -secret /Группа/Подгруппа/Имя
//
// Что важно понимать новичку:
//
//   - По умолчанию вывод оформлен для чтения человеком. Для скриптов есть
//     -raw (только значение), -field (одно поле) и -json (весь ответ).
//     Пример подстановки в переменную: PASSWORD=$(pamget ... -raw)
//   - Токен лучше не писать в командной строке: он виден в списке процессов
//     и попадает в историю оболочки. Используйте переменную PAM_TOKEN.
//   - Код возврата: 0 — успех, 1 — ошибка (текст ошибки уходит в stderr).
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/akprof2000/pam-client/pam"
)

// version подставляется при сборке через -ldflags "-X main.version=..."
// (см. scripts/release.sh). В обычной сборке остаётся "dev".
var version = "dev"

func main() {
	// main держим предельно коротким: вся работа в run, чтобы отложенные
	// вызовы (defer) успели отработать до os.Exit.
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "ошибка:", err)
		os.Exit(1)
	}
}

func run() error {
	// Каждый флаг возвращает указатель на значение; читать его нужно
	// уже после flag.Parse().
	var (
		server   = flag.String("server", pam.ServerFromEnv(), "адрес сервера PAM (по умолчанию из PAM_SERVER)")
		token    = flag.String("token", os.Getenv("PAM_TOKEN"), "токен AAPM (по умолчанию из PAM_TOKEN)")
		secret   = flag.String("secret", "", "полный путь секрета: /группа/имя")
		list     = flag.Bool("list", false, "показать записи, доступные токену, и выйти")
		insecure = flag.Bool("insecure", false, "не проверять TLS-сертификат сервера (по умолчанию проверяется)")
		caFile   = flag.String("ca", "", "файл с доверенным корневым сертификатом (PEM)")
		field    = flag.String("field", "", "вывести конкретное поле: username|password|data|ssl-certificate|ssh-key|passphrase")
		asJSON   = flag.Bool("json", false, "вывести весь ответ в JSON")
		raw      = flag.Bool("raw", false, "вывести только значение секрета, без оформления (для скриптов)")
		asEnv    = flag.Bool("env", false, "вывести все поля как присваивания переменных оболочки: eval \"$(pamget ... -env)\"")
		expire   = flag.Int("expire", 0, "срок жизни пароля в минутах (0 — значение клиента, отрицательное — не передавать)")
		change   = flag.Bool("change-required", false, "требовать смену пароля после выдачи")
		comment  = flag.String("comment", "", "комментарий для журнала аудита PAM")
		timeout  = flag.Duration("timeout", pam.DefaultTimeout, "таймаут одного запроса, например 5s")
		retries  = flag.Int("retries", pam.DefaultRetries, "число повторов при сетевых сбоях и ответах 429/5xx")
		showVer  = flag.Bool("version", false, "показать версию и выйти")
	)
	flag.Parse()

	if *showVer {
		fmt.Println("pamget", version)
		return nil
	}

	if *server == "" {
		flag.Usage()
		return fmt.Errorf("не задан адрес сервера: укажите -server или переменную %s", pam.ServerEnvVar)
	}
	if *secret == "" && !*list {
		flag.Usage()
		return fmt.Errorf("нужен -secret (или -list для перечня доступных записей)")
	}

	// Опции клиента собираем в срез и передаём в New одним «хвостом».
	opts := []pam.Option{
		pam.WithInsecureSkipVerify(*insecure),
		pam.WithTimeout(*timeout),
		pam.WithRetry(*retries, pam.DefaultRetryDelay),
	}
	if *caFile != "" {
		opts = append(opts, pam.WithCACertFile(*caFile))
	}
	if *comment != "" {
		opts = append(opts, pam.WithComment(*comment))
	}
	if *expire != 0 {
		opts = append(opts, pam.WithPasswordExpiration(*expire))
	}

	client, err := pam.New(*server, *token, opts...)
	if err != nil {
		return err
	}

	// Контекст ограничивает операцию целиком (вместе с повторами),
	// тогда как -timeout ограничивает один запрос.
	total := *timeout*time.Duration(*retries+1) + 5*time.Second
	ctx, cancel := context.WithTimeout(context.Background(), total)
	defer cancel()

	if *list {
		return printList(ctx, client, *asJSON)
	}
	return printSecret(ctx, client, *secret, *field, *asJSON, *raw, *asEnv, *change)
}

// printList печатает записи, доступные текущему токену.
func printList(ctx context.Context, client *pam.Client, asJSON bool) error {
	accounts, err := client.ListAccounts(ctx)
	if err != nil {
		return err
	}
	if asJSON {
		return encodeJSON(accounts)
	}
	printAccountsPretty(accounts)
	return nil
}

// printSecret получает секрет и печатает его в выбранном формате.
func printSecret(ctx context.Context, client *pam.Client, fullPath, field string, asJSON, raw, asEnv, changeRequired bool) error {
	// Путь вида /группа/имя разбивается на две части запроса.
	accountPath, accountName, err := pam.ParsePath(fullPath)
	if err != nil {
		return err
	}

	s, err := client.GetSecret(ctx, pam.Request{
		AccountPath:            accountPath,
		AccountName:            accountName,
		PasswordChangeRequired: changeRequired,
	})
	if err != nil {
		return err
	}

	switch {
	case asJSON:
		// Полный ответ: тип записи, секрет и метаданные.
		return encodeJSON(map[string]any{
			"kind":       s.Kind,
			"secret":     s.Raw,
			"properties": s.Properties,
		})

	case asEnv:
		// Все поля сразу — чтобы скрипту хватило одного запроса к PAM
		// (и одной записи в журнале аудита).
		printEnv(s)

	case field != "":
		// Конкретное поле — удобно для скриптов.
		v, ok := s.Raw[field]
		if !ok {
			return fmt.Errorf("в записи типа %q нет поля %q", s.Kind, field)
		}
		fmt.Println(v)

	case raw:
		// Только основное значение записи: пароль, данные, сертификат
		// или приватный ключ — без оформления и лишних строк.
		fmt.Println(s.String())

	default:
		// Обычный режим: аккуратно оформленный вывод для человека.
		printPretty(s, fullPath)
	}
	return nil
}

// encodeJSON печатает значение в stdout с отступами.
func encodeJSON(v any) error {
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(v)
}
