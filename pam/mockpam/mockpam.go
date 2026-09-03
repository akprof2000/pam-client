// Package mockpam — имитация AAPM REST API Kron PAM: отдаёт JSON той же формы,
// что и настоящий сервер. Используется в тестах и для локальной отладки
// (см. cmd/fakepam).
package mockpam

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Account — запись в имитированном хранилище.
type Account struct {
	// Path — путь группы, например "/Example/Common/Test/test_accounts".
	Path string
	// Name — имя записи.
	Name string
	// Secret — содержимое блока "secret" ответа.
	Secret map[string]string
	// SecretName попадает в properties.secretName; если пусто, берётся Name.
	SecretName string
}

// FullPath возвращает полный путь записи.
func (a Account) FullPath() string {
	return strings.TrimRight(a.Path, "/") + "/" + a.Name
}

// Handler — обработчик эндпоинта /sc-aapm-ui/rest/aapm/password.
type Handler struct {
	// Token — ожидаемый токен AAPM. Пустой отключает проверку.
	Token string

	mu       sync.RWMutex
	accounts map[string]Account
	// Requests хранит запросы, дошедшие до обработчика (для проверок в тестах).
	Requests []RecordedRequest
}

// RecordedRequest — зафиксированные параметры входящего запроса.
type RecordedRequest struct {
	Method                     string
	Path                       string
	Token                      string
	AccountPath                string
	AccountName                string
	Comment                    string
	ResponseType               string
	PasswordChangeRequired     string
	PasswordExpirationInMinute string
	ContentType                string
}

// NewHandler создаёт обработчик с заданным токеном и набором записей.
func NewHandler(token string, accounts ...Account) *Handler {
	h := &Handler{Token: token, accounts: make(map[string]Account, len(accounts))}
	for _, a := range accounts {
		h.Add(a)
	}
	return h
}

// Add добавляет или заменяет запись.
func (h *Handler) Add(a Account) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.accounts[a.FullPath()] = a
}

// Recorded возвращает копию списка обработанных запросов.
func (h *Handler) Recorded() []RecordedRequest {
	h.mu.RLock()
	defer h.mu.RUnlock()
	out := make([]RecordedRequest, len(h.Requests))
	copy(out, h.Requests)
	return out
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	rec := RecordedRequest{
		Method:                     r.Method,
		Path:                       r.URL.Path,
		Token:                      q.Get("token"),
		AccountPath:                q.Get("sapmAccountPath"),
		AccountName:                q.Get("sapmAccountName"),
		Comment:                    q.Get("comment"),
		ResponseType:               q.Get("responseType"),
		PasswordChangeRequired:     q.Get("passwordChangeRequired"),
		PasswordExpirationInMinute: q.Get("passwordExpirationInMinute"),
		ContentType:                r.Header.Get("Content-Type"),
	}
	h.mu.Lock()
	h.Requests = append(h.Requests, rec)
	h.mu.Unlock()

	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "only GET is supported")
		return
	}
	if h.Token != "" && rec.Token != h.Token {
		writeError(w, http.StatusUnauthorized, "invalid token")
		return
	}
	if rec.AccountPath == "" || rec.AccountName == "" {
		writeError(w, http.StatusBadRequest, "sapmAccountPath and sapmAccountName are required")
		return
	}
	if v := rec.PasswordExpirationInMinute; v != "" {
		if _, err := strconv.Atoi(v); err != nil {
			writeError(w, http.StatusBadRequest, "passwordExpirationInMinute must be a number")
			return
		}
	}

	full := strings.TrimRight(rec.AccountPath, "/") + "/" + rec.AccountName
	h.mu.RLock()
	acc, ok := h.accounts[full]
	h.mu.RUnlock()
	if !ok {
		writeError(w, http.StatusNotFound, fmt.Sprintf("account %s not found", full))
		return
	}

	name := acc.SecretName
	if name == "" {
		name = acc.Name
	}
	now := time.Now().UnixMilli()
	body := map[string]any{
		"secret": acc.Secret,
		"properties": map[string]any{
			"dbId":                   1234567891,
			"device":                 nil,
			"secretName":             name,
			"changePeriod":           nil,
			"description":            nil,
			"secretNotes":            nil,
			"nextChangeTime":         nil,
			"passwordSeenStatus":     "UNSEEN",
			"validationStatus":       nil,
			"secondPartSeenUsername": nil,
			"firstPartSeenUsername":  nil,
			"secretType":             "STATIC",
			"ownerEid":               "test_user",
			"ownerId":                "1a2b3c4d-a1b2-c3d4-e5f6-1a2b3c4d5e6f",
			"createdAt":              now,
			"updatedAt":              now,
			"approvalStatus":         nil,
			"groupFullPath":          acc.Path,
			"approvedBy":             nil,
			"approvedDate":           nil,
			"approvalRequired":       false,
		},
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(body)
}

func writeError(w http.ResponseWriter, code int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": msg})
}

// ListHandler отдаёт список записей, доступных токену (listSAPMAccounts).
func (h *Handler) ListHandler(w http.ResponseWriter, r *http.Request) {
	if h.Token != "" && r.URL.Query().Get("token") != h.Token {
		writeError(w, http.StatusUnauthorized, "invalid token")
		return
	}
	h.mu.RLock()
	list := make([]map[string]any, 0, len(h.accounts))
	for _, a := range h.accounts {
		name := a.SecretName
		if name == "" {
			name = a.Name
		}
		list = append(list, map[string]any{
			"dbId":          int64(1234567891),
			"secretName":    name,
			"secretType":    "STATIC",
			"groupFullPath": a.Path,
			"description":   nil,
		})
	}
	h.mu.RUnlock()

	sort.Slice(list, func(i, j int) bool {
		return list[i]["secretName"].(string) < list[j]["secretName"].(string)
	})
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(list)
}

// mux возвращает роутер, отвечающий по путям настоящего API.
func (h *Handler) mux() http.Handler {
	m := http.NewServeMux()
	m.Handle("/sc-aapm-ui/rest/aapm/password", h)
	m.HandleFunc("/sc-aapm-ui/rest/aapm/listSAPMAccounts", h.ListHandler)
	return m
}

// NewServer поднимает HTTP-сервер-имитацию (без TLS).
func NewServer(h *Handler) *httptest.Server {
	return httptest.NewServer(h.mux())
}

// NewTLSServer поднимает HTTPS-сервер-имитацию с самоподписанным сертификатом.
// Сертификат доступен через srv.Certificate() — им проверяется работа
// с включённой валидацией TLS.
func NewTLSServer(h *Handler) *httptest.Server {
	return httptest.NewTLSServer(h.mux())
}

// Демонстрационные записи, повторяющие примеры ответов из документации.
var (
	// UserCredentials — логин и пароль.
	UserCredentials = Account{
		Path:       "/Example/Common/Test/test_accounts",
		Name:       "static_user_credentials",
		SecretName: "static_user_credentials",
		Secret: map[string]string{
			"username": "example-username",
			"password": "example-password",
		},
	}
	// SecretData — произвольные данные (токен).
	SecretData = Account{
		Path:       "/Example/Common/Test/test_accounts",
		Name:       "static_secret_data",
		SecretName: "static_secret_data",
		Secret: map[string]string{
			"data": "example-secret-data",
		},
	}
	// SSLCertificate — PEM-сертификат.
	SSLCertificate = Account{
		Path:       "/Example/Common/Test/test_accounts",
		Name:       "static_ssl_certificate",
		SecretName: "static_ssl_certificate",
		Secret: map[string]string{
			"ssl-certificate": "-----BEGIN CERTIFICATE-----\nM3..M5\n-----END CERTIFICATE-----",
		},
	}
	// SSHKey — приватный ключ, парольная фраза и логин.
	SSHKey = Account{
		Path:       "/Example/Common/Test/test_accounts",
		Name:       "static_ssh_key",
		SecretName: "static_ssh_key",
		Secret: map[string]string{
			"ssh-key":    "-----BEGIN OPENSSH PRIVATE KEY-----\nb3...b4\n-----END OPENSSH PRIVATE KEY-----",
			"passphrase": "example-passphrase",
			"username":   "example-username",
		},
	}
)

// DemoAccounts возвращает все демонстрационные записи.
func DemoAccounts() []Account {
	return []Account{UserCredentials, SecretData, SSLCertificate, SSHKey}
}
