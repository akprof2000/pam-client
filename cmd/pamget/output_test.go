package main

// Тесты режима -env: от корректности экранирования зависит безопасность
// применения вывода через eval в скриптах.

import (
	"strings"
	"testing"
)

func TestEnvVarName(t *testing.T) {
	cases := map[string]string{
		"username":        "PAM_USERNAME",
		"password":        "PAM_PASSWORD",
		"data":            "PAM_DATA",
		"ssl-certificate": "PAM_SSL_CERTIFICATE",
		"ssh-key":         "PAM_SSH_KEY",
		"passphrase":      "PAM_PASSPHRASE",
		"some field.name": "PAM_SOME_FIELD_NAME",
	}
	for field, want := range cases {
		if got := envVarName(field); got != want {
			t.Errorf("envVarName(%q) = %q, ожидалось %q", field, got, want)
		}
	}
}

func TestShellQuote(t *testing.T) {
	cases := []struct {
		name  string
		value string
		want  string
	}{
		{"обычное значение", "password123", `'password123'`},
		{"пробелы", "two words", `'two words'`},
		{"доллар и обратные кавычки", "$USER `id`", "'$USER `id`'"},
		{"двойные кавычки", `a"b`, `'a"b'`},
		{"одинарная кавычка", "it's", `'it'\''s'`},
		{"перевод строки", "line1\nline2", "'line1\nline2'"},
		{"пустое значение", "", `''`},
		{"точка с запятой и подстановка", "a; rm -rf /; $(id)", `'a; rm -rf /; $(id)'`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := shellQuote(tc.value); got != tc.want {
				t.Errorf("shellQuote(%q) = %s, ожидалось %s", tc.value, got, tc.want)
			}
		})
	}
}

// Значение, заключённое shellQuote, при разборе оболочкой должно давать
// ровно исходную строку. Проверяем это правилом: внутри результата не может
// остаться неэкранированной одинарной кавычки, а «склейка» частей
// восстанавливает исходное значение.
func TestShellQuoteRoundTrip(t *testing.T) {
	values := []string{
		"simple",
		"it's",
		"'''",
		"a'b\"c$d`e",
		"-----BEGIN OPENSSH PRIVATE KEY-----\nb3\n-----END OPENSSH PRIVATE KEY-----",
	}
	for _, v := range values {
		quoted := shellQuote(v)
		if !strings.HasPrefix(quoted, "'") || !strings.HasSuffix(quoted, "'") {
			t.Errorf("shellQuote(%q) = %s: нет обрамляющих кавычек", v, quoted)
			continue
		}
		if got := unquoteShell(quoted); got != v {
			t.Errorf("разбор shellQuote(%q) дал %q", v, got)
		}
	}
}

// unquoteShell — минимальная модель разбора одинарных кавычек оболочкой:
// содержимое между кавычками берётся буквально, а последовательность
// '\” означает саму кавычку.
func unquoteShell(s string) string {
	var b strings.Builder
	inQuotes := false
	for i := 0; i < len(s); i++ {
		switch {
		case s[i] == '\'':
			inQuotes = !inQuotes
		case !inQuotes && s[i] == '\\' && i+1 < len(s):
			b.WriteByte(s[i+1])
			i++
		default:
			b.WriteByte(s[i])
		}
	}
	return b.String()
}
