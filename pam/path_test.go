package pam_test

import (
	"strings"
	"testing"

	"github.com/akprof2000/pam-client/pam"
)

// Разбор пути секрета: таблица нормальных и вырожденных случаев.
func TestParsePathTable(t *testing.T) {
	cases := []struct {
		in         string
		path, name string
		wantErr    bool
	}{
		{in: "/Path/to/my/account/accountname", path: "/Path/to/my/account", name: "accountname"},
		{in: "/group/name", path: "/group", name: "name"},
		{in: "/group/name/", path: "/group", name: "name"},
		{in: "  /group/name  ", path: "/group", name: "name"},
		{in: "/группа/имя", path: "/группа", name: "имя"},
		{in: "/g/n with spaces", path: "/g", name: "n with spaces"},
		{in: "/onlyroot", wantErr: true},
		{in: "name", wantErr: true},
		{in: "/", wantErr: true},
		{in: "//", wantErr: true},
		{in: "", wantErr: true},
		{in: "   ", wantErr: true},
	}
	for _, tc := range cases {
		p, n, err := pam.ParsePath(tc.in)
		if tc.wantErr {
			if err == nil {
				t.Errorf("ParsePath(%q): ожидалась ошибка, получено %q, %q", tc.in, p, n)
			}
			continue
		}
		if err != nil {
			t.Errorf("ParsePath(%q): %v", tc.in, err)
			continue
		}
		if p != tc.path || n != tc.name {
			t.Errorf("ParsePath(%q) = %q, %q; ожидалось %q, %q", tc.in, p, n, tc.path, tc.name)
		}
	}
}

// FuzzParsePath проверяет, что разбор пути не паникует ни на каком вводе,
// а успешный результат всегда собирается обратно в исходный путь.
func FuzzParsePath(f *testing.F) {
	for _, seed := range []string{"/g/n", "/a/b/c", "", "/", "///", "имя", "/g/n/"} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, in string) {
		p, n, err := pam.ParsePath(in)
		if err != nil {
			return
		}
		if p == "" || n == "" {
			t.Fatalf("ParsePath(%q) вернул пустые части: %q, %q", in, p, n)
		}
		if strings.Contains(n, "/") {
			t.Fatalf("ParsePath(%q): имя содержит слэш: %q", in, n)
		}
		if got := p + "/" + n; got != strings.TrimRight(strings.TrimSpace(in), "/") {
			t.Fatalf("ParsePath(%q): склейка даёт %q", in, got)
		}
	})
}
