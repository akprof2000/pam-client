package pam

import "testing"

func TestParseSecretPropertiesLoose(t *testing.T) {
	body := []byte(`{"secret":{"username":"u","password":"p"},
		"properties":{"dbId":7,"device":{"id":1,"name":"host"},"secretName":"acc",
		"changePeriod":"30","createdAt":1700000000000}}`)
	s, err := parseSecret(body)
	if err != nil {
		t.Fatalf("parseSecret: %v", err)
	}
	if s.Kind != KindUserCredentials || s.Password != "p" {
		t.Fatalf("секрет разобран неверно: %+v", s)
	}
	p := s.Properties
	if p.DBID != 7 || p.SecretName != "acc" || p.CreatedAt != 1700000000000 {
		t.Fatalf("свойства разобраны неверно: %+v", p)
	}
	if p.Device == nil || *p.Device != `{"id":1,"name":"host"}` {
		t.Fatalf("device: %v", p.Device)
	}
	if p.ChangePeriod != nil {
		t.Fatalf("changePeriod неверного типа должен пропускаться")
	}
}
