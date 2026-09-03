package pam_test

import (
	"context"
	"crypto/tls"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/akprof2000/pam-client/pam"
	"github.com/akprof2000/pam-client/pam/mockpam"
)

// DefaultTestDelay — минимальная пауза для тестов с повторами.
const DefaultTestDelay = 5 * time.Millisecond

func TestOptionValidation(t *testing.T) {
	cases := []struct {
		name    string
		opt     pam.Option
		wantErr bool
	}{
		{"нулевой таймаут", pam.WithTimeout(0), true},
		{"отрицательный таймаут", pam.WithTimeout(-time.Second), true},
		{"нормальный таймаут", pam.WithTimeout(time.Second), false},
		{"пустой путь", pam.WithPath(""), true},
		{"свой путь", pam.WithPath("/custom"), false},
		{"nil http-клиент", pam.WithHTTPClient(nil), true},
		{"свой http-клиент", pam.WithHTTPClient(&http.Client{}), false},
		{"битый CA", pam.WithCACertPEM([]byte("не PEM")), true},
		{"несуществующий файл CA", pam.WithCACertFile(filepath.Join(t.TempDir(), "нет.pem")), true},
		{"отрицательное число повторов", pam.WithRetry(-1, time.Second), true},
		{"нулевая пауза повтора", pam.WithRetry(1, 0), true},
		{"корректные повторы", pam.WithRetry(3, time.Second), false},
		{"клиентский сертификат: нет файла", pam.WithClientCert("нет.crt", "нет.key"), true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := pam.New("https://host", testToken, tc.opt)
			if tc.wantErr && err == nil {
				t.Error("ожидалась ошибка")
			}
			if !tc.wantErr && err != nil {
				t.Errorf("неожиданная ошибка: %v", err)
			}
		})
	}
}

// Адрес сервера принимается с разными схемами и с путём-префиксом.
func TestServerAddressForms(t *testing.T) {
	h := mockpam.NewHandler(testToken, mockpam.DemoAccounts()...)
	srv := mockpam.NewServer(h)
	t.Cleanup(srv.Close)

	for _, form := range []string{srv.URL, strings.TrimPrefix(srv.URL, "http://")} {
		// Без схемы клиент подставит https, поэтому проверяем только разбор адреса.
		if _, err := pam.New(form, testToken); err != nil {
			t.Errorf("New(%q): %v", form, err)
		}
	}
	if _, err := pam.New("://плохой", testToken); err == nil {
		t.Error("некорректный адрес должен отвергаться")
	}
	if _, err := pam.New("https://", testToken); err == nil {
		t.Error("адрес без хоста должен отвергаться")
	}
}

// Свой путь эндпоинта и базовый URL с префиксом пути.
func TestCustomPathAndPrefix(t *testing.T) {
	var gotPath string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		_, _ = w.Write([]byte(`{"secret":{"data":"x"},"properties":{}}`))
	}))
	t.Cleanup(srv.Close)

	c, err := pam.New(srv.URL+"/prefix", testToken, pam.WithPath("/api/password"))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if _, err := c.Get(context.Background(), "/g/n"); err != nil {
		t.Fatalf("Get: %v", err)
	}
	if gotPath != "/prefix/api/password" {
		t.Errorf("путь запроса = %q", gotPath)
	}
}

func TestUserAgentAndHeaders(t *testing.T) {
	var ua, accept string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ua, accept = r.Header.Get("User-Agent"), r.Header.Get("Accept")
		_, _ = w.Write([]byte(`{"secret":{"data":"x"},"properties":{}}`))
	}))
	t.Cleanup(srv.Close)

	c, err := pam.New(srv.URL, testToken, pam.WithUserAgent("my-app/2.0"))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if _, err := c.Get(context.Background(), "/g/n"); err != nil {
		t.Fatalf("Get: %v", err)
	}
	if ua != "my-app/2.0" {
		t.Errorf("User-Agent = %q", ua)
	}
	if accept != "application/json" {
		t.Errorf("Accept = %q", accept)
	}
}

// Проверка сертификата включена по умолчанию: подменённый http-клиент не
// применяется молча, а TLS-настройки клиента действуют на транспорт.
func TestTLSDefaultsToVerification(t *testing.T) {
	c, err := pam.New("https://host", testToken)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	// Достаём транспорт через тестовый сервер: строгий клиент обязан упасть.
	srv := mockpam.NewTLSServer(mockpam.NewHandler(testToken, mockpam.DemoAccounts()...))
	t.Cleanup(srv.Close)

	strict, err := pam.New(srv.URL, testToken, pam.WithRetry(0, DefaultTestDelay))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if _, err := strict.Get(context.Background(), mockpam.SecretData.FullPath()); err == nil {
		t.Fatal("самоподписанный сертификат должен отвергаться по умолчанию")
	}
	_ = c
}

// WithHTTPClient полностью заменяет транспорт, включая настройки TLS.
func TestWithHTTPClientOverridesTransport(t *testing.T) {
	srv := mockpam.NewTLSServer(mockpam.NewHandler(testToken, mockpam.DemoAccounts()...))
	t.Cleanup(srv.Close)

	custom := &http.Client{
		Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}},
		Timeout:   5 * time.Second,
	}
	c, err := pam.New(srv.URL, testToken, pam.WithHTTPClient(custom))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if _, err := c.Get(context.Background(), mockpam.SecretData.FullPath()); err != nil {
		t.Fatalf("Get: %v", err)
	}
}

func TestWithCACertFile(t *testing.T) {
	srv := mockpam.NewTLSServer(mockpam.NewHandler(testToken, mockpam.DemoAccounts()...))
	t.Cleanup(srv.Close)

	path := filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(path, certPEM(t, srv.Certificate().Raw), 0o600); err != nil {
		t.Fatalf("запись CA: %v", err)
	}
	c, err := pam.New(srv.URL, testToken, pam.WithCACertFile(path))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if _, err := c.Get(context.Background(), mockpam.SecretData.FullPath()); err != nil {
		t.Fatalf("Get с доверенным CA: %v", err)
	}
}

// Таймаут клиента прерывает медленный ответ.
func TestTimeout(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(300 * time.Millisecond)
		_, _ = w.Write([]byte(`{"secret":{"data":"x"},"properties":{}}`))
	}))
	t.Cleanup(srv.Close)

	c, err := pam.New(srv.URL, testToken,
		pam.WithTimeout(50*time.Millisecond), pam.WithRetry(0, DefaultTestDelay))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if _, err := c.Get(context.Background(), "/g/n"); err == nil {
		t.Fatal("ожидался таймаут")
	}
}

// Дедлайн контекста имеет приоритет над повторами.
func TestContextDeadlineStopsRetries(t *testing.T) {
	var calls int
	var mu sync.Mutex
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		calls++
		mu.Unlock()
		http.Error(w, "unavailable", http.StatusServiceUnavailable)
	}))
	t.Cleanup(srv.Close)

	c, err := pam.New(srv.URL, testToken, pam.WithRetry(10, 50*time.Millisecond))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Millisecond)
	defer cancel()

	start := time.Now()
	if _, err := c.Get(ctx, "/g/n"); err == nil {
		t.Fatal("ожидалась ошибка")
	}
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Errorf("повторы не прекратились по дедлайну: %v", elapsed)
	}
	mu.Lock()
	defer mu.Unlock()
	if calls > 5 {
		t.Errorf("слишком много попыток: %d", calls)
	}
}

// Повторы исчерпываются и возвращают последнюю ошибку сервера.
func TestRetryExhausted(t *testing.T) {
	var calls int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		http.Error(w, "too many requests", http.StatusTooManyRequests)
	}))
	t.Cleanup(srv.Close)

	c, err := pam.New(srv.URL, testToken, pam.WithRetry(2, DefaultTestDelay))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	_, err = c.Get(context.Background(), "/g/n")
	var httpErr *pam.HTTPError
	if !errorsAs(err, &httpErr) || httpErr.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("ожидался 429: %v", err)
	}
	if calls != 3 {
		t.Errorf("попыток = %d, ожидалось 3 (1 + 2 повтора)", calls)
	}
}

// Ошибка проверки сертификата не повторяется — это не временный сбой.
func TestNoRetryOnTLSError(t *testing.T) {
	h := mockpam.NewHandler(testToken, mockpam.DemoAccounts()...)
	srv := mockpam.NewTLSServer(h)
	t.Cleanup(srv.Close)

	c, err := pam.New(srv.URL, testToken, pam.WithRetry(3, 200*time.Millisecond))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	start := time.Now()
	if _, err := c.Get(context.Background(), mockpam.SecretData.FullPath()); err == nil {
		t.Fatal("ожидалась ошибка TLS")
	}
	if elapsed := time.Since(start); elapsed > 300*time.Millisecond {
		t.Errorf("похоже, были повторы: %v", elapsed)
	}
}

// Валидация параметров запроса до обращения к сети.
func TestRequestValidation(t *testing.T) {
	h := mockpam.NewHandler(testToken, mockpam.DemoAccounts()...)
	c := newTestClient(t, h)

	cases := []pam.Request{
		{AccountName: "n"},
		{AccountPath: "/g"},
		{AccountPath: "   ", AccountName: "n"},
		{},
	}
	for i, r := range cases {
		if _, err := c.GetSecret(context.Background(), r); err == nil {
			t.Errorf("случай %d: ожидалась ошибка валидации", i)
		}
	}
	if n := len(h.Recorded()); n != 0 {
		t.Errorf("запросы не должны уходить на сервер, ушло: %d", n)
	}
}

// Клиент безопасен для параллельного использования.
func TestConcurrentUse(t *testing.T) {
	h := mockpam.NewHandler(testToken, mockpam.DemoAccounts()...)
	c := newTestClient(t, h)

	var wg sync.WaitGroup
	errs := make(chan error, 40)
	for i := 0; i < 40; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			acc := mockpam.DemoAccounts()[i%4]
			s, err := c.Get(context.Background(), acc.FullPath())
			if err != nil {
				errs <- err
				return
			}
			if s.Kind == pam.KindUnknown {
				errs <- errUnknownKind
			}
		}(i)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Errorf("параллельный запрос: %v", err)
	}
}

// Токен не должен утекать в текст ошибок ни при каком сценарии.
func TestTokenNeverLeaks(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "boom", http.StatusInternalServerError)
	}))
	t.Cleanup(srv.Close)

	c, err := pam.New(srv.URL, testToken, pam.WithRetry(0, DefaultTestDelay))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	_, err = c.Get(context.Background(), "/g/n")
	if err == nil {
		t.Fatal("ожидалась ошибка")
	}
	if strings.Contains(err.Error(), testToken) {
		t.Errorf("токен в тексте ошибки: %v", err)
	}
}
