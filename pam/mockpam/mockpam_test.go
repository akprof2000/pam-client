package mockpam_test

// Тесты самой имитации сервера: она должна вести себя как настоящий API,
// иначе тесты клиента будут проверять фикцию.

import (
	"encoding/json"
	"io"
	"net/http"
	"testing"

	"github.com/akprof2000/pam-client/pam/mockpam"
)

const token = "00000000-0000-0000-0000-000000000001"

func get(t *testing.T, url string) (int, []byte) {
	t.Helper()
	resp, err := http.Get(url)
	if err != nil {
		t.Fatalf("GET %s: %v", url, err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("чтение тела: %v", err)
	}
	return resp.StatusCode, body
}

// Форма ответа должна совпадать с примерами из документации PAM.
func TestResponseShape(t *testing.T) {
	h := mockpam.NewHandler(token, mockpam.DemoAccounts()...)
	srv := mockpam.NewServer(h)
	defer srv.Close()

	url := srv.URL + "/sc-aapm-ui/rest/aapm/password" +
		"?token=" + token +
		"&sapmAccountPath=" + mockpam.UserCredentials.Path +
		"&sapmAccountName=" + mockpam.UserCredentials.Name +
		"&responseType=JSON"

	code, body := get(t, url)
	if code != http.StatusOK {
		t.Fatalf("код = %d, тело = %s", code, body)
	}

	var payload struct {
		Secret     map[string]string `json:"secret"`
		Properties map[string]any    `json:"properties"`
	}
	if err := json.Unmarshal(body, &payload); err != nil {
		t.Fatalf("ответ не разбирается: %v", err)
	}
	if payload.Secret["username"] != "example-username" || payload.Secret["password"] != "example-password" {
		t.Errorf("secret = %v", payload.Secret)
	}
	for _, key := range []string{"dbId", "secretName", "secretType", "groupFullPath", "createdAt", "updatedAt", "approvalRequired"} {
		if _, ok := payload.Properties[key]; !ok {
			t.Errorf("в properties нет поля %q", key)
		}
	}
}

func TestErrorCases(t *testing.T) {
	h := mockpam.NewHandler(token, mockpam.DemoAccounts()...)
	srv := mockpam.NewServer(h)
	defer srv.Close()

	base := srv.URL + "/sc-aapm-ui/rest/aapm/password"
	cases := []struct {
		name string
		url  string
		want int
	}{
		{"неверный токен", base + "?token=bad&sapmAccountPath=/a&sapmAccountName=b", http.StatusUnauthorized},
		{"нет параметров", base + "?token=" + token, http.StatusBadRequest},
		{"нечисловой expiration", base + "?token=" + token +
			"&sapmAccountPath=" + mockpam.SecretData.Path +
			"&sapmAccountName=" + mockpam.SecretData.Name +
			"&passwordExpirationInMinute=abc", http.StatusBadRequest},
		{"нет такой записи", base + "?token=" + token + "&sapmAccountPath=/a&sapmAccountName=b", http.StatusNotFound},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if code, body := get(t, tc.url); code != tc.want {
				t.Errorf("код = %d, ожидался %d, тело = %s", code, tc.want, body)
			}
		})
	}
}

func TestListEndpoint(t *testing.T) {
	h := mockpam.NewHandler(token, mockpam.DemoAccounts()...)
	srv := mockpam.NewServer(h)
	defer srv.Close()

	code, body := get(t, srv.URL+"/sc-aapm-ui/rest/aapm/listSAPMAccounts?token="+token)
	if code != http.StatusOK {
		t.Fatalf("код = %d, тело = %s", code, body)
	}
	var list []map[string]any
	if err := json.Unmarshal(body, &list); err != nil {
		t.Fatalf("ответ не разбирается: %v", err)
	}
	if len(list) != len(mockpam.DemoAccounts()) {
		t.Errorf("записей = %d", len(list))
	}

	if code, _ := get(t, srv.URL+"/sc-aapm-ui/rest/aapm/listSAPMAccounts?token=bad"); code != http.StatusUnauthorized {
		t.Errorf("код при неверном токене = %d", code)
	}
}

// Пустой токен в обработчике означает «не проверять» — удобно для отладки.
func TestEmptyTokenDisablesCheck(t *testing.T) {
	h := mockpam.NewHandler("", mockpam.DemoAccounts()...)
	srv := mockpam.NewServer(h)
	defer srv.Close()

	url := srv.URL + "/sc-aapm-ui/rest/aapm/password" +
		"?sapmAccountPath=" + mockpam.SecretData.Path +
		"&sapmAccountName=" + mockpam.SecretData.Name
	if code, body := get(t, url); code != http.StatusOK {
		t.Errorf("код = %d, тело = %s", code, body)
	}
}

// Add добавляет и заменяет записи, Recorded фиксирует пришедшие параметры.
func TestAddAndRecorded(t *testing.T) {
	h := mockpam.NewHandler(token)
	srv := mockpam.NewServer(h)
	defer srv.Close()

	h.Add(mockpam.Account{Path: "/my/group", Name: "acc", Secret: map[string]string{"data": "v1"}})
	url := srv.URL + "/sc-aapm-ui/rest/aapm/password?token=" + token +
		"&sapmAccountPath=/my/group&sapmAccountName=acc&comment=hello"
	if code, _ := get(t, url); code != http.StatusOK {
		t.Fatalf("код = %d", code)
	}

	h.Add(mockpam.Account{Path: "/my/group", Name: "acc", Secret: map[string]string{"data": "v2"}})
	_, body := get(t, url)
	var payload struct {
		Secret map[string]string `json:"secret"`
	}
	if err := json.Unmarshal(body, &payload); err != nil {
		t.Fatalf("разбор: %v", err)
	}
	if payload.Secret["data"] != "v2" {
		t.Errorf("запись не заменилась: %v", payload.Secret)
	}

	rec := h.Recorded()
	if len(rec) != 2 {
		t.Fatalf("зафиксировано запросов: %d", len(rec))
	}
	if rec[0].Comment != "hello" || rec[0].AccountName != "acc" {
		t.Errorf("параметры зафиксированы неверно: %+v", rec[0])
	}
}

// POST не поддерживается — как и у настоящего эндпоинта.
func TestMethodNotAllowed(t *testing.T) {
	h := mockpam.NewHandler(token, mockpam.DemoAccounts()...)
	srv := mockpam.NewServer(h)
	defer srv.Close()

	resp, err := http.Post(srv.URL+"/sc-aapm-ui/rest/aapm/password?token="+token, "application/json", nil)
	if err != nil {
		t.Fatalf("POST: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Errorf("код = %d", resp.StatusCode)
	}
}
