package pam_test

// Вспомогательные функции для тестов пакета.

import (
	"bytes"
	"encoding/pem"
	"errors"
	"strings"
	"testing"
)

// errUnknownKind сигнализирует о нераспознанном типе записи в параллельном тесте.
var errUnknownKind = errors.New("тип записи не распознан")

// certPEM превращает DER-сертификат тестового сервера в PEM,
// пригодный для pam.WithCACertPEM.
func certPEM(t *testing.T, der []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	if err := pem.Encode(&buf, &pem.Block{Type: "CERTIFICATE", Bytes: der}); err != nil {
		t.Fatalf("pem.Encode: %v", err)
	}
	return buf.Bytes()
}

// errorsAs — короткая обёртка над errors.As для читаемости проверок.
func errorsAs(err error, target any) bool { return errors.As(err, target) }

func contains(haystack, needle string) bool { return strings.Contains(haystack, needle) }
