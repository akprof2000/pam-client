package pam_test

import (
	"context"
	"crypto/x509"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/akprof2000/pam-client/pam"
	"github.com/akprof2000/pam-client/pam/mockpam"
)

const testToken = "00000000-0000-0000-0000-000000000001"

func newTestClient(t *testing.T, h *mockpam.Handler, opts ...pam.Option) *pam.Client {
	t.Helper()
	srv := mockpam.NewServer(h)
	t.Cleanup(srv.Close)
	c, err := pam.New(srv.URL, testToken, opts...)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return c
}

func TestGetUserCredentials(t *testing.T) {
	h := mockpam.NewHandler(testToken, mockpam.DemoAccounts()...)
	c := newTestClient(t, h)

	s, err := c.Get(context.Background(), mockpam.UserCredentials.FullPath())
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if s.Kind != pam.KindUserCredentials {
		t.Errorf("Kind = %q, ожидался %q", s.Kind, pam.KindUserCredentials)
	}
	if s.Username != "example-username" || s.Password != "example-password" {
		t.Errorf("логин/пароль = %q/%q", s.Username, s.Password)
	}
	if s.String() != "example-password" {
		t.Errorf("String() = %q", s.String())
	}
	if s.Properties.SecretName != "static_user_credentials" {
		t.Errorf("secretName = %q", s.Properties.SecretName)
	}
	if s.Properties.CreatedAt.Time().IsZero() {
		t.Error("createdAt не разобран")
	}
}

func TestGetSecretData(t *testing.T) {
	h := mockpam.NewHandler(testToken, mockpam.DemoAccounts()...)
	c := newTestClient(t, h)

	s, err := c.Get(context.Background(), mockpam.SecretData.FullPath())
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if s.Kind != pam.KindSecretData {
		t.Errorf("Kind = %q", s.Kind)
	}
	if s.Data != "example-secret-data" || s.String() != s.Data {
		t.Errorf("Data = %q", s.Data)
	}
}

func TestGetSSLCertificate(t *testing.T) {
	h := mockpam.NewHandler(testToken, mockpam.DemoAccounts()...)
	c := newTestClient(t, h)

	s, err := c.Get(context.Background(), mockpam.SSLCertificate.FullPath())
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if s.Kind != pam.KindSSLCertificate {
		t.Errorf("Kind = %q", s.Kind)
	}
	if want := "-----BEGIN CERTIFICATE-----\nM3..M5\n-----END CERTIFICATE-----"; s.Certificate != want {
		t.Errorf("Certificate = %q", s.Certificate)
	}
}

func TestGetSSHKey(t *testing.T) {
	h := mockpam.NewHandler(testToken, mockpam.DemoAccounts()...)
	c := newTestClient(t, h)

	s, err := c.Get(context.Background(), mockpam.SSHKey.FullPath())
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if s.Kind != pam.KindSSHKey {
		t.Errorf("Kind = %q", s.Kind)
	}
	if s.Passphrase != "example-passphrase" || s.Username != "example-username" {
		t.Errorf("passphrase/username = %q/%q", s.Passphrase, s.Username)
	}
	if s.PrivateKey == "" {
		t.Error("приватный ключ пуст")
	}
}

func TestRequestParameters(t *testing.T) {
	h := mockpam.NewHandler(testToken, mockpam.DemoAccounts()...)
	c := newTestClient(t, h, pam.WithComment("default-comment"))

	_, err := c.GetSecret(context.Background(), pam.Request{
		AccountPath:                mockpam.SecretData.Path,
		AccountName:                mockpam.SecretData.Name,
		PasswordExpirationInMinute: 30,
		PasswordChangeRequired:     true,
		Comment:                    "job-42",
	})
	if err != nil {
		t.Fatalf("GetSecret: %v", err)
	}
	rec := h.Recorded()
	if len(rec) != 1 {
		t.Fatalf("запросов: %d", len(rec))
	}
	r := rec[0]
	switch {
	case r.Method != http.MethodGet:
		t.Errorf("метод = %s", r.Method)
	case r.Path != pam.DefaultPath:
		t.Errorf("путь = %s", r.Path)
	case r.Token != testToken:
		t.Errorf("token = %s", r.Token)
	case r.AccountPath != mockpam.SecretData.Path:
		t.Errorf("sapmAccountPath = %s", r.AccountPath)
	case r.AccountName != mockpam.SecretData.Name:
		t.Errorf("sapmAccountName = %s", r.AccountName)
	case r.ResponseType != "JSON":
		t.Errorf("responseType = %s", r.ResponseType)
	case r.PasswordChangeRequired != "true":
		t.Errorf("passwordChangeRequired = %s", r.PasswordChangeRequired)
	case r.PasswordExpirationInMinute != "30":
		t.Errorf("passwordExpirationInMinute = %s", r.PasswordExpirationInMinute)
	case r.Comment != "job-42":
		t.Errorf("comment = %s", r.Comment)
	case r.ContentType != "application/json":
		t.Errorf("Content-Type = %s", r.ContentType)
	}
}

func TestDefaultCommentUsedWhenEmpty(t *testing.T) {
	h := mockpam.NewHandler(testToken, mockpam.DemoAccounts()...)
	c := newTestClient(t, h, pam.WithComment("default-comment"))

	if _, err := c.Get(context.Background(), mockpam.SecretData.FullPath()); err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got := h.Recorded()[0].Comment; got != "default-comment" {
		t.Errorf("comment = %q", got)
	}
}

// Без явных настроек клиент шлёт те же значения, что и Python-библиотека:
// комментарий и срок жизни пароля присутствуют всегда.
func TestBuiltinDefaultsSent(t *testing.T) {
	h := mockpam.NewHandler(testToken, mockpam.DemoAccounts()...)
	c := newTestClient(t, h)

	if _, err := c.Get(context.Background(), mockpam.SecretData.FullPath()); err != nil {
		t.Fatalf("Get: %v", err)
	}
	r := h.Recorded()[0]
	if r.Comment != pam.DefaultComment {
		t.Errorf("comment = %q, ожидался %q", r.Comment, pam.DefaultComment)
	}
	if r.PasswordExpirationInMinute != "30" {
		t.Errorf("passwordExpirationInMinute = %q", r.PasswordExpirationInMinute)
	}
}

// Отрицательное значение отключает передачу срока жизни пароля.
func TestPasswordExpirationDisabled(t *testing.T) {
	h := mockpam.NewHandler(testToken, mockpam.DemoAccounts()...)
	c := newTestClient(t, h, pam.WithPasswordExpiration(-1))

	if _, err := c.Get(context.Background(), mockpam.SecretData.FullPath()); err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got := h.Recorded()[0].PasswordExpirationInMinute; got != "" {
		t.Errorf("passwordExpirationInMinute = %q, ожидалось отсутствие", got)
	}
}

func TestListAccounts(t *testing.T) {
	h := mockpam.NewHandler(testToken, mockpam.DemoAccounts()...)
	c := newTestClient(t, h)

	list, err := c.ListAccounts(context.Background())
	if err != nil {
		t.Fatalf("ListAccounts: %v", err)
	}
	if len(list) != len(mockpam.DemoAccounts()) {
		t.Fatalf("записей: %d", len(list))
	}
	want := mockpam.SecretData.FullPath()
	var found bool
	for _, a := range list {
		if a.FullPath() == want {
			found = true
			if a.SecretType != "STATIC" || a.DBID == 0 || a.Raw == nil {
				t.Errorf("запись разобрана неполно: %+v", a)
			}
		}
	}
	if !found {
		t.Errorf("в списке нет %s", want)
	}

	// Полученный путь пригоден для Get.
	if _, err := c.Get(context.Background(), want); err != nil {
		t.Errorf("Get по пути из списка: %v", err)
	}
}

// Повтор выполняется на 503 и не выполняется на 404.
func TestRetry(t *testing.T) {
	var calls int
	flaky := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if calls < 3 {
			http.Error(w, "temporarily unavailable", http.StatusServiceUnavailable)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"secret":{"data":"ok"},"properties":{}}`))
	}))
	t.Cleanup(flaky.Close)

	c, err := pam.New(flaky.URL, testToken, pam.WithRetry(2, 10*time.Millisecond))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	s, err := c.Get(context.Background(), "/group/name")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if s.Data != "ok" || calls != 3 {
		t.Errorf("data = %q, попыток = %d", s.Data, calls)
	}

	h := mockpam.NewHandler(testToken, mockpam.DemoAccounts()...)
	strict := newTestClient(t, h, pam.WithRetry(3, 10*time.Millisecond))
	if _, err := strict.Get(context.Background(), "/Example/Common/Test/test_accounts/nope"); err == nil {
		t.Fatal("ожидалась ошибка 404")
	}
	if n := len(h.Recorded()); n != 1 {
		t.Errorf("404 не должен повторяться, запросов: %d", n)
	}
}

func TestBadTokenAndMissingAccount(t *testing.T) {
	h := mockpam.NewHandler(testToken, mockpam.DemoAccounts()...)
	srv := mockpam.NewServer(h)
	t.Cleanup(srv.Close)

	bad, err := pam.New(srv.URL, "wrong-token")
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	_, err = bad.Get(context.Background(), mockpam.SecretData.FullPath())
	var httpErr *pam.HTTPError
	if !errors.As(err, &httpErr) || httpErr.StatusCode != http.StatusUnauthorized {
		t.Fatalf("ожидался 401, получено: %v", err)
	}

	good, err := pam.New(srv.URL, testToken)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	_, err = good.Get(context.Background(), "/Example/Common/Test/test_accounts/nope")
	if !errors.As(err, &httpErr) || httpErr.StatusCode != http.StatusNotFound {
		t.Fatalf("ожидался 404, получено: %v", err)
	}
}

// TLS-сертификат имитации самоподписанный: без доверия к нему запрос должен
// падать, с WithCACertPEM или WithInsecureSkipVerify — проходить.
func TestTLSVerification(t *testing.T) {
	h := mockpam.NewHandler(testToken, mockpam.DemoAccounts()...)
	srv := mockpam.NewTLSServer(h)
	t.Cleanup(srv.Close)

	strict, err := pam.New(srv.URL, testToken)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if _, err := strict.Get(context.Background(), mockpam.SecretData.FullPath()); err == nil {
		t.Fatal("ожидалась ошибка проверки сертификата")
	} else {
		var unknown x509.UnknownAuthorityError
		var hostErr x509.HostnameError
		if !errors.As(err, &unknown) && !errors.As(err, &hostErr) {
			t.Fatalf("ожидалась ошибка TLS, получено: %v", err)
		}
	}

	skip, err := pam.New(srv.URL, testToken, pam.WithInsecureSkipVerify(true))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if _, err := skip.Get(context.Background(), mockpam.SecretData.FullPath()); err != nil {
		t.Fatalf("с отключённой проверкой: %v", err)
	}

	pemData := certPEM(t, srv.Certificate().Raw)
	trusting, err := pam.New(srv.URL, testToken, pam.WithCACertPEM(pemData))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if _, err := trusting.Get(context.Background(), mockpam.SecretData.FullPath()); err != nil {
		t.Fatalf("с доверенным CA: %v", err)
	}
}

func TestTokenRedactedInTransportError(t *testing.T) {
	c, err := pam.New("https://127.0.0.1:1", testToken, pam.WithTimeout(time.Second))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	_, err = c.Get(context.Background(), "/group/name")
	if err == nil {
		t.Fatal("ожидалась ошибка соединения")
	}
	if contains(err.Error(), testToken) {
		t.Errorf("токен попал в текст ошибки: %v", err)
	}
}

func TestParsePath(t *testing.T) {
	cases := []struct {
		in         string
		path, name string
		wantErr    bool
	}{
		{in: "/Path/to/my/account/accountname", path: "/Path/to/my/account", name: "accountname"},
		{in: "/group/name/", path: "/group", name: "name"},
		{in: "/onlyroot", wantErr: true},
		{in: "", wantErr: true},
	}
	for _, tc := range cases {
		p, n, err := pam.ParsePath(tc.in)
		if tc.wantErr {
			if err == nil {
				t.Errorf("ParsePath(%q): ожидалась ошибка", tc.in)
			}
			continue
		}
		if err != nil {
			t.Errorf("ParsePath(%q): %v", tc.in, err)
			continue
		}
		if p != tc.path || n != tc.name {
			t.Errorf("ParsePath(%q) = %q, %q", tc.in, p, n)
		}
	}
}

func TestNewValidation(t *testing.T) {
	// Пустой адрес берётся из PAM_SERVER; без него — ошибка.
	t.Setenv(pam.ServerEnvVar, "")
	if _, err := pam.New("", testToken); err == nil {
		t.Error("без адреса сервера New должен возвращать ошибку")
	}
	t.Setenv(pam.ServerEnvVar, "https://pam.example.com")
	if _, err := pam.New("", testToken); err != nil {
		t.Errorf("адрес из %s: %v", pam.ServerEnvVar, err)
	}
	if _, err := pam.New("https://host", ""); err == nil {
		t.Error("пустой токен должен отвергаться")
	}
	// Схема по умолчанию — https.
	if _, err := pam.New("pam.example.ru", testToken); err != nil {
		t.Errorf("адрес без схемы: %v", err)
	}
}

func TestContextCancel(t *testing.T) {
	h := mockpam.NewHandler(testToken, mockpam.DemoAccounts()...)
	c := newTestClient(t, h)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := c.Get(ctx, mockpam.SecretData.FullPath()); !errors.Is(err, context.Canceled) {
		t.Fatalf("ожидался context.Canceled, получено: %v", err)
	}
}
