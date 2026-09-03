package pam

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

// Kind описывает тип записи, полученной из хранилища.
//
// В API PAM нет отдельного поля «тип секрета»: тип определяется по набору
// ключей внутри объекта "secret". Поэтому мы определяем его сами — см.
// parseSecret ниже.
type Kind string

const (
	// KindUserCredentials — Static User Credentials: логин + пароль.
	KindUserCredentials Kind = "user_credentials"
	// KindSecretData — Static Secret Data: произвольные данные (токен и т.п.).
	KindSecretData Kind = "secret_data"
	// KindSSLCertificate — Static SSL Certificate: PEM-сертификат.
	KindSSLCertificate Kind = "ssl_certificate"
	// KindSSHKey — Static SSH Key: приватный ключ, passphrase, логин.
	KindSSHKey Kind = "ssh_key"
	// KindUnknown — набор полей не распознан; значения доступны через Secret.Raw.
	KindUnknown Kind = "unknown"
)

// Ключи объекта "secret" в ответе AAPM.
const (
	fieldUsername    = "username"
	fieldPassword    = "password"
	fieldData        = "data"
	fieldCertificate = "ssl-certificate"
	fieldSSHKey      = "ssh-key"
	fieldPassphrase  = "passphrase"
)

// Secret — разобранный ответ AAPM. Заполняются только поля, соответствующие Kind;
// исходный объект всегда доступен в Raw.
type Secret struct {
	Kind Kind

	// KindUserCredentials, KindSSHKey.
	Username string
	// KindUserCredentials.
	Password string
	// KindSecretData — токен или иные данные.
	Data string
	// KindSSLCertificate — PEM-сертификат.
	Certificate string
	// KindSSHKey — приватный ключ и парольная фраза к нему.
	PrivateKey string
	Passphrase string

	// Raw — объект "secret" как он пришёл от сервера.
	Raw map[string]string
	// Properties — метаданные записи.
	Properties Properties
}

// Properties — блок "properties" ответа AAPM.
type Properties struct {
	DBID                   int64    `json:"dbId"`
	Device                 *string  `json:"device"`
	SecretName             string   `json:"secretName"`
	ChangePeriod           *int64   `json:"changePeriod"`
	Description            *string  `json:"description"`
	SecretNotes            *string  `json:"secretNotes"`
	NextChangeTime         *EpochMS `json:"nextChangeTime"`
	PasswordSeenStatus     string   `json:"passwordSeenStatus"`
	ValidationStatus       *string  `json:"validationStatus"`
	SecondPartSeenUsername *string  `json:"secondPartSeenUsername"`
	FirstPartSeenUsername  *string  `json:"firstPartSeenUsername"`
	SecretType             string   `json:"secretType"`
	OwnerEID               string   `json:"ownerEid"`
	OwnerID                string   `json:"ownerId"`
	CreatedAt              EpochMS  `json:"createdAt"`
	UpdatedAt              EpochMS  `json:"updatedAt"`
	ApprovalStatus         *string  `json:"approvalStatus"`
	GroupFullPath          string   `json:"groupFullPath"`
	ApprovedBy             *string  `json:"approvedBy"`
	ApprovedDate           *EpochMS `json:"approvedDate"`
	ApprovalRequired       bool     `json:"approvalRequired"`
}

// EpochMS — время в миллисекундах Unix, как его отдаёт AAPM.
//
// Отдельный тип нужен, чтобы поля времени разбирались из числа автоматически,
// а вызывающий получал обычный time.Time через метод Time().
type EpochMS int64

// Time возвращает значение как time.Time в локальной зоне.
func (e EpochMS) Time() time.Time { return time.UnixMilli(int64(e)) }

// String возвращает секретное значение записи: пароль, данные, сертификат или
// приватный ключ — в зависимости от типа. Для неизвестного типа — пустая строка.
func (s Secret) String() string {
	switch s.Kind {
	case KindUserCredentials:
		return s.Password
	case KindSecretData:
		return s.Data
	case KindSSLCertificate:
		return s.Certificate
	case KindSSHKey:
		return s.PrivateKey
	}
	return ""
}

// AccountInfo — запись из списка доступных токену аккаунтов (listSAPMAccounts).
// Состав полей у разных версий PAM отличается, поэтому исходный объект
// сохраняется в Raw.
type AccountInfo struct {
	DBID          int64  `json:"dbId"`
	SecretName    string `json:"secretName"`
	SecretType    string `json:"secretType"`
	GroupFullPath string `json:"groupFullPath"`
	Description   string `json:"description"`

	// Raw — объект записи как он пришёл от сервера.
	Raw map[string]any `json:"-"`
}

// FullPath возвращает полный путь записи для Client.Get.
func (a AccountInfo) FullPath() string {
	if a.GroupFullPath == "" || a.SecretName == "" {
		return ""
	}
	return strings.TrimRight(a.GroupFullPath, "/") + "/" + a.SecretName
}

// parseAccountList разбирает ответ listSAPMAccounts. Допускается как массив
// записей, так и объект с массивом в одном из полей.
func parseAccountList(body []byte) ([]AccountInfo, error) {
	items, err := accountItems(body)
	if err != nil {
		return nil, err
	}
	out := make([]AccountInfo, 0, len(items))
	for _, item := range items {
		var a AccountInfo
		if err := json.Unmarshal(item, &a); err != nil {
			return nil, fmt.Errorf("pam: разбор записи списка: %w", err)
		}
		_ = json.Unmarshal(item, &a.Raw)
		out = append(out, a)
	}
	return out, nil
}

func accountItems(body []byte) ([]json.RawMessage, error) {
	var items []json.RawMessage
	if err := json.Unmarshal(body, &items); err == nil {
		return items, nil
	}
	// Некоторые версии заворачивают список в объект — берём первый массив.
	var wrapper map[string]json.RawMessage
	if err := json.Unmarshal(body, &wrapper); err != nil {
		return nil, fmt.Errorf("pam: разбор списка записей: %w", err)
	}
	for _, v := range wrapper {
		var nested []json.RawMessage
		if err := json.Unmarshal(v, &nested); err == nil {
			return nested, nil
		}
	}
	return nil, fmt.Errorf("pam: в ответе listSAPMAccounts не найден список записей")
}

// rawResponse — форма ответа REST API.
type rawResponse struct {
	Secret     map[string]string `json:"secret"`
	Properties Properties        `json:"properties"`
}

// parseSecret разбирает тело ответа AAPM и определяет тип записи.
//
// Важно: значения секрета остаются строками. В Python-аналоге здесь
// выполняется json.loads для каждой строки, из-за чего пароль "12345"
// превращается в число, а секрет с JSON внутри — в структуру.
func parseSecret(body []byte) (*Secret, error) {
	var raw rawResponse
	dec := json.NewDecoder(strings.NewReader(string(body)))
	if err := dec.Decode(&raw); err != nil {
		return nil, fmt.Errorf("pam: разбор ответа: %w", err)
	}
	if len(raw.Secret) == 0 {
		return nil, fmt.Errorf("pam: ответ не содержит объект secret")
	}

	s := &Secret{
		Raw:         raw.Secret,
		Properties:  raw.Properties,
		Username:    raw.Secret[fieldUsername],
		Password:    raw.Secret[fieldPassword],
		Data:        raw.Secret[fieldData],
		Certificate: raw.Secret[fieldCertificate],
		PrivateKey:  raw.Secret[fieldSSHKey],
		Passphrase:  raw.Secret[fieldPassphrase],
	}

	// Порядок проверок важен: запись с ssh-ключом содержит ещё и username,
	// а иногда и passphrase, поэтому сначала проверяем самые «узкие» типы
	// и только потом общие.
	switch {
	case s.PrivateKey != "":
		s.Kind = KindSSHKey
	case s.Certificate != "":
		s.Kind = KindSSLCertificate
	case s.Password != "":
		s.Kind = KindUserCredentials
	case s.Data != "":
		s.Kind = KindSecretData
	default:
		s.Kind = KindUnknown
	}
	return s, nil
}
