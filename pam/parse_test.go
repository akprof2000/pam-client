package pam_test

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/akprof2000/pam-client/pam"
)

// rawServer поднимает сервер, отдающий заданное тело с заданным кодом.
func rawServer(t *testing.T, status int, body string) *pam.Client {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(srv.Close)
	c, err := pam.New(srv.URL, testToken, pam.WithRetry(0, DefaultTestDelay))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return c
}

// Определение типа записи по набору полей в объекте secret.
func TestKindDetection(t *testing.T) {
	cases := []struct {
		name   string
		secret string
		want   pam.Kind
		value  string
	}{
		{"логин и пароль", `{"username":"u","password":"p"}`, pam.KindUserCredentials, "p"},
		{"только данные", `{"data":"tok"}`, pam.KindSecretData, "tok"},
		{"сертификат", `{"ssl-certificate":"cert"}`, pam.KindSSLCertificate, "cert"},
		{"ssh-ключ", `{"ssh-key":"key","passphrase":"pp","username":"u"}`, pam.KindSSHKey, "key"},
		{"ssh-ключ важнее сертификата", `{"ssh-key":"key","ssl-certificate":"cert"}`, pam.KindSSHKey, "key"},
		{"неизвестный набор полей", `{"somethingElse":"x"}`, pam.KindUnknown, ""},
		{"пустые значения", `{"password":""}`, pam.KindUnknown, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := rawServer(t, http.StatusOK, fmt.Sprintf(`{"secret":%s,"properties":{}}`, tc.secret))
			s, err := c.Get(context.Background(), "/g/n")
			if err != nil {
				t.Fatalf("Get: %v", err)
			}
			if s.Kind != tc.want {
				t.Errorf("Kind = %q, ожидался %q", s.Kind, tc.want)
			}
			if s.String() != tc.value {
				t.Errorf("String() = %q, ожидалось %q", s.String(), tc.value)
			}
			if s.Raw == nil {
				t.Error("Raw не заполнен")
			}
		})
	}
}

// Значения секрета остаются строками, даже если похожи на JSON или число.
// Python-версия (sincon/data_tools.prepare_data) в этом месте молча
// десериализует такие значения — здесь этого быть не должно.
func TestSecretValuesStayStrings(t *testing.T) {
	c := rawServer(t, http.StatusOK,
		`{"secret":{"data":"{\"k\":1}"},"properties":{}}`)
	s, err := c.Get(context.Background(), "/g/n")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if s.Data != `{"k":1}` {
		t.Errorf("Data = %q, ожидалась исходная строка", s.Data)
	}

	c = rawServer(t, http.StatusOK, `{"secret":{"password":"12345","username":"u"},"properties":{}}`)
	s, err = c.Get(context.Background(), "/g/n")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if s.Password != "12345" {
		t.Errorf("Password = %q, ожидалась строка", s.Password)
	}
}

func TestBadResponses(t *testing.T) {
	cases := []struct {
		name string
		body string
	}{
		{"не JSON", `<html>error</html>`},
		{"обрезанный JSON", `{"secret":{"data":"x"`},
		{"нет объекта secret", `{"properties":{}}`},
		{"пустой объект secret", `{"secret":{},"properties":{}}`},
		{"пустое тело", ``},
		{"secret не объект", `{"secret":"строка"}`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := rawServer(t, http.StatusOK, tc.body)
			if _, err := c.Get(context.Background(), "/g/n"); err == nil {
				t.Fatal("ожидалась ошибка разбора")
			}
		})
	}
}

// Метаданные разбираются полностью, включая nullable-поля и время.
func TestPropertiesParsing(t *testing.T) {
	body := `{"secret":{"data":"x"},"properties":{
		"dbId":1234567892,"device":null,"secretName":"static_secret_data",
		"changePeriod":null,"description":null,"secretNotes":null,"nextChangeTime":null,
		"passwordSeenStatus":"UNSEEN","validationStatus":null,"secretType":"STATIC",
		"ownerEid":"test_user","ownerId":"1a2b3c4d-a1b2-c3d4-e5f6-1a2b3c4d5e6f",
		"createdAt":1666261466918,"updatedAt":1666266789618,"approvalStatus":null,
		"groupFullPath":"/Example/Common/Test/test_accounts","approvedBy":null,
		"approvedDate":null,"approvalRequired":false}}`
	c := rawServer(t, http.StatusOK, body)
	s, err := c.Get(context.Background(), "/g/n")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	p := s.Properties
	if p.DBID != 1234567892 || p.SecretName != "static_secret_data" || p.SecretType != "STATIC" {
		t.Errorf("properties разобраны неверно: %+v", p)
	}
	if p.GroupFullPath != "/Example/Common/Test/test_accounts" {
		t.Errorf("groupFullPath = %q", p.GroupFullPath)
	}
	if p.Device != nil || p.ApprovedDate != nil || p.NextChangeTime != nil {
		t.Error("null-поля должны оставаться nil")
	}
	if p.ApprovalRequired {
		t.Error("approvalRequired должен быть false")
	}
	if got := p.CreatedAt.Time().UTC().Format("2006-01-02"); got != "2022-10-20" {
		t.Errorf("createdAt = %s", got)
	}
	if !p.UpdatedAt.Time().After(p.CreatedAt.Time()) {
		t.Error("updatedAt должен быть позже createdAt")
	}
}

// Ошибка не-200 приходит типом *HTTPError с телом ответа.
func TestHTTPErrorDetails(t *testing.T) {
	c := rawServer(t, http.StatusForbidden, `{"error":"access denied"}`)
	_, err := c.Get(context.Background(), "/g/n")
	var httpErr *pam.HTTPError
	if err == nil || !errorsAs(err, &httpErr) {
		t.Fatalf("ожидался *pam.HTTPError, получено: %v", err)
	}
	if httpErr.StatusCode != http.StatusForbidden {
		t.Errorf("StatusCode = %d", httpErr.StatusCode)
	}
	if !strings.Contains(httpErr.Body, "access denied") {
		t.Errorf("Body = %q", httpErr.Body)
	}
	if !strings.Contains(httpErr.Error(), "403") {
		t.Errorf("текст ошибки = %q", httpErr.Error())
	}
}

// Очень длинное тело ошибки обрезается в тексте, но сохраняется целиком в поле.
func TestHTTPErrorTruncation(t *testing.T) {
	long := strings.Repeat("x", 2000)
	c := rawServer(t, http.StatusInternalServerError, long)
	_, err := c.Get(context.Background(), "/g/n")
	var httpErr *pam.HTTPError
	if !errorsAs(err, &httpErr) {
		t.Fatalf("ожидался *pam.HTTPError: %v", err)
	}
	if len(httpErr.Body) != 2000 {
		t.Errorf("Body усечён: %d", len(httpErr.Body))
	}
	if len(httpErr.Error()) > 700 {
		t.Errorf("текст ошибки не обрезан: %d символов", len(httpErr.Error()))
	}
}

// Список записей принимается и как массив, и как объект с вложенным массивом.
func TestListAccountsShapes(t *testing.T) {
	item := `{"dbId":1,"secretName":"n","secretType":"STATIC","groupFullPath":"/g","description":"d"}`
	cases := []struct {
		name string
		body string
		ok   bool
	}{
		{"массив", "[" + item + "]", true},
		{"объект со списком", `{"accounts":[` + item + `]}`, true},
		{"пустой массив", `[]`, true},
		{"нет списка", `{"total":0}`, false},
		{"не JSON", `oops`, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := rawServer(t, http.StatusOK, tc.body)
			list, err := c.ListAccounts(context.Background())
			if !tc.ok {
				if err == nil {
					t.Fatal("ожидалась ошибка")
				}
				return
			}
			if err != nil {
				t.Fatalf("ListAccounts: %v", err)
			}
			if len(list) > 0 && list[0].FullPath() != "/g/n" {
				t.Errorf("FullPath = %q", list[0].FullPath())
			}
		})
	}
}

// FullPath не должен собирать мусор из неполной записи.
func TestAccountInfoFullPathIncomplete(t *testing.T) {
	c := rawServer(t, http.StatusOK, `[{"dbId":1,"secretName":"n"}]`)
	list, err := c.ListAccounts(context.Background())
	if err != nil {
		t.Fatalf("ListAccounts: %v", err)
	}
	if got := list[0].FullPath(); got != "" {
		t.Errorf("FullPath = %q, ожидалась пустая строка", got)
	}
}
