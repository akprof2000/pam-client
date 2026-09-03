package main

// Здесь собрано всё, что отвечает за внешний вид вывода в консоли.
// Логика запроса к PAM живёт в main.go и об оформлении ничего не знает.

import (
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/akprof2000/pam-client/pam"
)

// Цвета включаются только когда вывод идёт в терминал. Если результат
// перенаправлен в файл или в другую команду, escape-последовательности
// испортили бы значение секрета, поэтому там они отключаются.
// Стандарт NO_COLOR (https://no-color.org) тоже уважаем.
var colorEnabled = isTerminal(os.Stdout) && os.Getenv("NO_COLOR") == ""

// isTerminal определяет, является ли файл терминалом. Дополнительных
// библиотек для этого не нужно: у символьного устройства выставлен
// бит ModeCharDevice.
func isTerminal(f *os.File) bool {
	info, err := f.Stat()
	if err != nil {
		return false
	}
	return info.Mode()&os.ModeCharDevice != 0
}

// Коды ANSI. Если цвет выключен, функции возвращают строку без изменений.
func paint(code, s string) string {
	if !colorEnabled {
		return s
	}
	return "\x1b[" + code + "m" + s + "\x1b[0m"
}

func bold(s string) string   { return paint("1", s) }
func dim(s string) string    { return paint("2", s) }
func cyan(s string) string   { return paint("36", s) }
func green(s string) string  { return paint("32", s) }
func yellow(s string) string { return paint("33", s) }

// kindTitle — человеческое название типа записи.
func kindTitle(k pam.Kind) string {
	switch k {
	case pam.KindUserCredentials:
		return "логин и пароль"
	case pam.KindSecretData:
		return "данные (токен)"
	case pam.KindSSLCertificate:
		return "SSL-сертификат"
	case pam.KindSSHKey:
		return "SSH-ключ"
	default:
		return "неизвестный тип"
	}
}

// fieldTitle — человеческое название поля секрета.
func fieldTitle(name string) string {
	switch name {
	case "username":
		return "логин"
	case "password":
		return "пароль"
	case "data":
		return "данные"
	case "ssl-certificate":
		return "сертификат"
	case "ssh-key":
		return "приватный ключ"
	case "passphrase":
		return "парольная фраза"
	default:
		return name
	}
}

// printPretty выводит секрет в читаемом виде: заголовок, поля, метаданные.
func printPretty(s *pam.Secret, fullPath string) {
	fmt.Println()
	fmt.Printf("  %s  %s\n", bold(cyan("СЕКРЕТ")), bold(fullPath))
	fmt.Printf("  %s     %s\n", dim("тип"), kindTitle(s.Kind))
	fmt.Println()

	// Поля печатаем в предсказуемом порядке: сначала известные, затем
	// всё остальное по алфавиту — так вывод не «прыгает» между запусками.
	order := []string{"username", "password", "data", "passphrase", "ssl-certificate", "ssh-key"}
	printed := make(map[string]bool, len(s.Raw))

	width := 0
	for name := range s.Raw {
		if n := len([]rune(fieldTitle(name))); n > width {
			width = n
		}
	}

	printField := func(name, value string) {
		title := fieldTitle(name)
		pad := strings.Repeat(" ", width-len([]rune(title)))
		if strings.Contains(value, "\n") {
			// Многострочные значения (ключи, сертификаты) печатаем блоком,
			// иначе они разъедутся по колонкам.
			fmt.Printf("  %s%s  %s\n", green(title), pad, dim("(многострочное значение)"))
			for _, line := range strings.Split(strings.TrimRight(value, "\n"), "\n") {
				fmt.Printf("    %s\n", line)
			}
			return
		}
		fmt.Printf("  %s%s  %s\n", green(title), pad, value)
	}

	for _, name := range order {
		if v, ok := s.Raw[name]; ok {
			printField(name, v)
			printed[name] = true
		}
	}
	rest := make([]string, 0, len(s.Raw))
	for name := range s.Raw {
		if !printed[name] {
			rest = append(rest, name)
		}
	}
	sort.Strings(rest)
	for _, name := range rest {
		printField(name, s.Raw[name])
	}

	// Метаданные показываем только те, что реально пришли от сервера.
	p := s.Properties
	meta := make([]string, 0, 4)
	if p.SecretType != "" {
		meta = append(meta, "тип записи: "+p.SecretType)
	}
	if p.GroupFullPath != "" {
		meta = append(meta, "группа: "+p.GroupFullPath)
	}
	if p.UpdatedAt != 0 {
		meta = append(meta, "изменён: "+p.UpdatedAt.Time().Format("2006-01-02 15:04:05"))
	}
	if p.OwnerEID != "" {
		meta = append(meta, "владелец: "+p.OwnerEID)
	}
	if len(meta) > 0 {
		fmt.Println()
		fmt.Printf("  %s\n", dim(strings.Join(meta, "   ")))
	}
	fmt.Println()
}

// printAccountsPretty выводит список доступных записей таблицей.
func printAccountsPretty(accounts []pam.AccountInfo) {
	if len(accounts) == 0 {
		fmt.Println()
		fmt.Println("  " + yellow("токену не доступна ни одна запись"))
		fmt.Println()
		return
	}

	// Ширину первой колонки считаем по самому длинному пути.
	width := 0
	paths := make([]string, len(accounts))
	for i, a := range accounts {
		p := a.FullPath()
		if p == "" {
			p = a.SecretName
		}
		paths[i] = p
		if n := len([]rune(p)); n > width {
			width = n
		}
	}

	fmt.Println()
	fmt.Printf("  %s  %s\n", bold(cyan("ДОСТУПНЫЕ ЗАПИСИ")), dim(fmt.Sprintf("(%d)", len(accounts))))
	fmt.Println()
	for i, a := range accounts {
		pad := strings.Repeat(" ", width-len([]rune(paths[i])))
		fmt.Printf("  %s%s  %s\n", paths[i], pad, dim(a.SecretType))
	}
	fmt.Println()
}

// envVarName превращает имя поля секрета в имя переменной окружения:
// "ssl-certificate" -> "PAM_SSL_CERTIFICATE".
func envVarName(field string) string {
	name := strings.ToUpper(strings.NewReplacer("-", "_", ".", "_", " ", "_").Replace(field))
	return "PAM_" + name
}

// shellQuote заключает значение в одинарные кавычки для оболочки.
// Внутри одинарных кавычек не действует ничего, кроме самой кавычки,
// поэтому её заменяем на последовательность '\” — так безопасно
// передаются и многострочные ключи, и значения со спецсимволами.
func shellQuote(v string) string {
	return "'" + strings.ReplaceAll(v, "'", `'\''`) + "'"
}

// printEnv печатает присваивания переменных оболочки: один запрос к PAM —
// все поля записи сразу. Применяется через eval:
//
//	eval "$(pamget -secret /группа/имя -env)"
//	echo "$PAM_USERNAME" "$PAM_PASSWORD"
func printEnv(s *pam.Secret) {
	names := make([]string, 0, len(s.Raw))
	for name := range s.Raw {
		names = append(names, name)
	}
	sort.Strings(names)

	for _, name := range names {
		fmt.Printf("%s=%s\n", envVarName(name), shellQuote(s.Raw[name]))
	}
	// Тип записи тоже пригодится: по нему скрипт понимает, что именно пришло.
	fmt.Printf("PAM_KIND=%s\n", shellQuote(string(s.Kind)))
}
