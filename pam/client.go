// Package pam — клиент AAPM REST API (Kron PAM) для получения секретов
// приложениями: логин/пароль, произвольные данные (токен), SSL-сертификат
// или SSH-ключ.
package pam

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"
)

// DefaultServer — адрес сервера PAM по умолчанию. Пустой, чтобы адрес
// конкретной установки не был зашит в исходный код. Задать его можно:
//
//   - переменной окружения PAM_SERVER (см. ServerFromEnv);
//   - при сборке:
//     go build -ldflags "-X github.com/akprof2000/pam-client/pam.DefaultServer=https://pam.example.com"
//
// Если адрес не задан ни одним способом, New вернёт ошибку.
var DefaultServer = ""

// ServerEnvVar — переменная окружения с адресом сервера PAM.
const ServerEnvVar = "PAM_SERVER"

// ServerFromEnv возвращает адрес сервера из переменной окружения PAM_SERVER,
// а если она пуста — значение DefaultServer (может быть задано при сборке).
func ServerFromEnv() string {
	if v := strings.TrimSpace(os.Getenv(ServerEnvVar)); v != "" {
		return v
	}
	return DefaultServer
}

// DefaultPath — путь эндпоинта выдачи секрета относительно адреса сервера.
const DefaultPath = "/sc-aapm-ui/rest/aapm/password"

// ListPath — путь эндпоинта со списком доступных токену записей.
const ListPath = "/sc-aapm-ui/rest/aapm/listSAPMAccounts"

// DefaultTimeout — таймаут HTTP-запроса по умолчанию.
const DefaultTimeout = 30 * time.Second

// DefaultPasswordExpiration — срок жизни выданного пароля в минутах,
// передаваемый по умолчанию.
const DefaultPasswordExpiration = 30

// DefaultComment — комментарий для журнала аудита PAM по умолчанию.
const DefaultComment = "Reading secret via go pam client"

// DefaultRetries — число повторов запроса при сетевых сбоях и временных
// ответах сервера (429, 5xx).
const DefaultRetries = 2

// DefaultRetryDelay — пауза перед первым повтором; далее удваивается.
const DefaultRetryDelay = 200 * time.Millisecond

// maxBodySize ограничивает объём читаемого ответа.
const maxBodySize = 4 << 20 // 4 MiB

// Client — клиент AAPM.
//
// Создаётся один раз на приложение и переиспользуется: внутри лежит
// *http.Client, который держит пул соединений. Все поля неизменяемы после
// New, поэтому клиента можно свободно вызывать из нескольких горутин.
type Client struct {
	baseURL    *url.URL
	path       string
	token      string
	http       *http.Client
	tls        *tls.Config
	timeout    time.Duration
	comment    string
	userAgent  string
	expiration int
	retries    int
	retryDelay time.Duration
}

// Option — необязательный параметр конструктора New.
//
// Это распространённый в Go приём «функциональные опции»: вместо огромного
// конструктора с десятком аргументов вызывающий передаёт только то, что ему
// нужно, — New(server, token, WithTimeout(5*time.Second), WithCACertFile(...)).
// Каждая опция получает наполовину собранного клиента и либо меняет его,
// либо возвращает ошибку.
type Option func(*Client) error

// WithInsecureSkipVerify отключает проверку сертификата сервера.
// По умолчанию проверка включена; отключать только для тестовых стендов.
func WithInsecureSkipVerify(skip bool) Option {
	return func(c *Client) error {
		c.tls.InsecureSkipVerify = skip
		return nil
	}
}

// WithCACertFile добавляет корневой сертификат (PEM) для проверки сервера.
func WithCACertFile(path string) Option {
	return func(c *Client) error {
		pemData, err := os.ReadFile(path)
		if err != nil {
			return fmt.Errorf("pam: чтение CA-сертификата: %w", err)
		}
		return WithCACertPEM(pemData)(c)
	}
}

// WithCACertPEM добавляет корневой сертификат из PEM-данных.
// Может вызываться несколько раз; заменяет системный пул на указанный набор.
func WithCACertPEM(pemData []byte) Option {
	return func(c *Client) error {
		if c.tls.RootCAs == nil {
			c.tls.RootCAs = x509.NewCertPool()
		}
		if !c.tls.RootCAs.AppendCertsFromPEM(pemData) {
			return errors.New("pam: не удалось разобрать CA-сертификат (PEM)")
		}
		return nil
	}
}

// WithClientCert настраивает взаимную TLS-аутентификацию.
func WithClientCert(certFile, keyFile string) Option {
	return func(c *Client) error {
		cert, err := tls.LoadX509KeyPair(certFile, keyFile)
		if err != nil {
			return fmt.Errorf("pam: клиентский сертификат: %w", err)
		}
		c.tls.Certificates = append(c.tls.Certificates, cert)
		return nil
	}
}

// WithTimeout задаёт таймаут запроса.
func WithTimeout(d time.Duration) Option {
	return func(c *Client) error {
		if d <= 0 {
			return errors.New("pam: таймаут должен быть положительным")
		}
		c.timeout = d
		return nil
	}
}

// WithPath переопределяет путь эндпоинта (по умолчанию DefaultPath).
func WithPath(p string) Option {
	return func(c *Client) error {
		if p == "" {
			return errors.New("pam: пустой путь эндпоинта")
		}
		c.path = p
		return nil
	}
}

// WithHTTPClient подставляет собственный *http.Client. При этом настройки TLS
// и таймаута из других опций не применяются — их задаёт вызывающая сторона.
func WithHTTPClient(h *http.Client) Option {
	return func(c *Client) error {
		if h == nil {
			return errors.New("pam: http-клиент не задан")
		}
		c.http = h
		return nil
	}
}

// WithComment задаёт комментарий по умолчанию для журнала аудита PAM.
func WithComment(s string) Option {
	return func(c *Client) error {
		c.comment = s
		return nil
	}
}

// WithPasswordExpiration задаёт срок жизни выданного пароля в минутах для всех
// запросов клиента. Отрицательное значение отключает передачу параметра —
// действует настройка сервера.
func WithPasswordExpiration(minutes int) Option {
	return func(c *Client) error {
		c.expiration = minutes
		return nil
	}
}

// WithRetry настраивает повторы при сетевых сбоях и временных ответах сервера
// (429, 5xx). retries — число повторов сверх первой попытки, delay — пауза
// перед первым повтором (далее удваивается). retries = 0 отключает повторы.
func WithRetry(retries int, delay time.Duration) Option {
	return func(c *Client) error {
		if retries < 0 {
			return errors.New("pam: число повторов не может быть отрицательным")
		}
		if delay <= 0 {
			return errors.New("pam: пауза между повторами должна быть положительной")
		}
		c.retries = retries
		c.retryDelay = delay
		return nil
	}
}

// WithUserAgent задаёт заголовок User-Agent.
func WithUserAgent(s string) Option {
	return func(c *Client) error {
		c.userAgent = s
		return nil
	}
}

// New создаёт клиента. server — адрес сервера PAM; пустая строка означает
// DefaultServer. token — токен AAPM-аккаунта.
// По умолчанию TLS-сертификат сервера проверяется.
func New(server, token string, opts ...Option) (*Client, error) {
	server = strings.TrimSpace(server)
	if server == "" {
		server = ServerFromEnv()
	}
	if server == "" {
		return nil, fmt.Errorf("pam: не задан адрес сервера (аргумент, %s или -ldflags)", ServerEnvVar)
	}
	if strings.TrimSpace(token) == "" {
		return nil, errors.New("pam: не задан токен")
	}
	if !strings.Contains(server, "://") {
		server = "https://" + server
	}
	u, err := url.Parse(server)
	if err != nil {
		return nil, fmt.Errorf("pam: адрес сервера: %w", err)
	}
	if u.Host == "" {
		return nil, fmt.Errorf("pam: адрес сервера %q не содержит хост", server)
	}

	c := &Client{
		baseURL:    u,
		path:       DefaultPath,
		token:      token,
		tls:        &tls.Config{MinVersion: tls.VersionTLS12},
		timeout:    DefaultTimeout,
		userAgent:  "go-pam-client/1.0",
		comment:    DefaultComment,
		expiration: DefaultPasswordExpiration,
		retries:    DefaultRetries,
		retryDelay: DefaultRetryDelay,
	}
	for _, opt := range opts {
		if err := opt(c); err != nil {
			return nil, err
		}
	}
	// Свой http.Client собираем только если его не подставили опцией.
	// Клонируем стандартный транспорт, чтобы получить разумные настройки
	// пула соединений, и подменяем в нём TLS-конфигурацию.
	if c.http == nil {
		tr := http.DefaultTransport.(*http.Transport).Clone()
		tr.TLSClientConfig = c.tls
		c.http = &http.Client{Transport: tr, Timeout: c.timeout}
	}
	return c, nil
}

// Request — параметры запроса секрета.
type Request struct {
	// AccountPath — путь группы аккаунта в PAM, например "/Example/Common/Test".
	AccountPath string
	// AccountName — имя записи внутри группы.
	AccountName string
	// Comment попадает в журнал аудита; если пусто, берётся из WithComment
	// либо DefaultComment.
	Comment string
	// PasswordExpirationInMinute — срок жизни выданного пароля в минутах.
	// 0 — значение клиента (WithPasswordExpiration, по умолчанию
	// DefaultPasswordExpiration); отрицательное — параметр не передаётся
	// и действует настройка сервера.
	PasswordExpirationInMinute int
	// PasswordChangeRequired — требовать смену пароля после выдачи.
	PasswordChangeRequired bool
}

// ParsePath разбивает полный путь секрета вида "/Path/to/group/accountName"
// на путь группы и имя записи.
func ParsePath(full string) (accountPath, accountName string, err error) {
	full = strings.TrimRight(strings.TrimSpace(full), "/")
	i := strings.LastIndex(full, "/")
	if i <= 0 || i == len(full)-1 {
		return "", "", fmt.Errorf("pam: путь секрета %q должен иметь вид /группа/имя", full)
	}
	return full[:i], full[i+1:], nil
}

// Get запрашивает секрет по полному пути вида "/Path/to/group/accountName".
func (c *Client) Get(ctx context.Context, fullPath string) (*Secret, error) {
	p, n, err := ParsePath(fullPath)
	if err != nil {
		return nil, err
	}
	return c.GetSecret(ctx, Request{AccountPath: p, AccountName: n})
}

// GetSecret запрашивает секрет с явно заданными параметрами.
func (c *Client) GetSecret(ctx context.Context, r Request) (*Secret, error) {
	if strings.TrimSpace(r.AccountPath) == "" {
		return nil, errors.New("pam: не задан путь аккаунта")
	}
	if strings.TrimSpace(r.AccountName) == "" {
		return nil, errors.New("pam: не задано имя аккаунта")
	}

	q := url.Values{}
	q.Set("sapmAccountPath", r.AccountPath)
	q.Set("sapmAccountName", r.AccountName)
	q.Set("responseType", "JSON")
	q.Set("passwordChangeRequired", strconv.FormatBool(r.PasswordChangeRequired))

	expiration := r.PasswordExpirationInMinute
	if expiration == 0 {
		expiration = c.expiration
	}
	if expiration > 0 {
		q.Set("passwordExpirationInMinute", strconv.Itoa(expiration))
	}

	comment := r.Comment
	if comment == "" {
		comment = c.comment
	}
	if comment != "" {
		q.Set("comment", comment)
	}

	body, err := c.do(ctx, c.path, q)
	if err != nil {
		return nil, err
	}
	return parseSecret(body)
}

// ListAccounts возвращает записи, доступные текущему AAPM-токену
// (эндпоинт listSAPMAccounts).
func (c *Client) ListAccounts(ctx context.Context) ([]AccountInfo, error) {
	body, err := c.do(ctx, ListPath, url.Values{})
	if err != nil {
		return nil, err
	}
	return parseAccountList(body)
}

// do выполняет GET-запрос к эндпоинту и возвращает тело успешного ответа.
// Токен добавляется здесь, чтобы не попадать в логи и тексты ошибок вызывающих.
func (c *Client) do(ctx context.Context, path string, q url.Values) ([]byte, error) {
	q.Set("token", c.token)

	u := *c.baseURL
	u.Path = strings.TrimRight(u.Path, "/") + path
	u.RawQuery = q.Encode()

	var lastErr error
	for attempt := 0; ; attempt++ {
		// Перед каждой повторной попыткой ждём: пауза удваивается
		// (200мс, 400мс, 800мс...) — это «экспоненциальная выдержка».
		// select здесь нужен, чтобы отмена контекста прерывала ожидание
		// сразу, а не после истечения паузы.
		if attempt > 0 {
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-time.After(c.retryDelay << (attempt - 1)):
			}
		}

		body, err := c.attempt(ctx, u.String())
		if err == nil {
			return body, nil
		}
		lastErr = err
		if attempt >= c.retries || !isRetryable(err) || ctx.Err() != nil {
			return nil, lastErr
		}
	}
}

// attempt выполняет один HTTP-запрос.
func (c *Client) attempt(ctx context.Context, rawURL string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return nil, fmt.Errorf("pam: формирование запроса: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", c.userAgent)

	resp, err := c.http.Do(req)
	if err != nil {
		// Токен передаётся в query — вычищаем его из текста ошибки.
		return nil, fmt.Errorf("pam: запрос к серверу: %w", &redactedError{err: err, secret: c.token})
	}
	defer resp.Body.Close()

	// LimitReader страхует от аномально большого ответа: без него сервер
	// (или прокси) может заставить нас прочитать в память сколько угодно.
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxBodySize))
	if err != nil {
		return nil, fmt.Errorf("pam: чтение ответа: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, &HTTPError{StatusCode: resp.StatusCode, Body: strings.TrimSpace(string(body))}
	}
	return body, nil
}

// isRetryable сообщает, имеет ли смысл повторить запрос: сетевые сбои и
// временные ответы сервера. Ошибки авторизации и «не найдено» не повторяются.
func isRetryable(err error) bool {
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return false
	}
	var httpErr *HTTPError
	if errors.As(err, &httpErr) {
		switch httpErr.StatusCode {
		case http.StatusTooManyRequests, http.StatusInternalServerError,
			http.StatusBadGateway, http.StatusServiceUnavailable, http.StatusGatewayTimeout:
			return true
		}
		return false
	}
	// Ошибка проверки сертификата повторной попыткой не лечится.
	var certErr *tls.CertificateVerificationError
	if errors.As(err, &certErr) {
		return false
	}
	var unknownAuthority x509.UnknownAuthorityError
	var hostErr x509.HostnameError
	if errors.As(err, &unknownAuthority) || errors.As(err, &hostErr) {
		return false
	}
	return true
}

// HTTPError — сервер вернул код, отличный от 200.
type HTTPError struct {
	StatusCode int
	Body       string
}

func (e *HTTPError) Error() string {
	b := e.Body
	const limit = 512
	if len(b) > limit {
		b = b[:limit] + "..."
	}
	return fmt.Sprintf("pam: сервер вернул %d %s: %s", e.StatusCode, http.StatusText(e.StatusCode), b)
}

// redactedError скрывает токен в тексте вложенной ошибки.
//
// Зачем: библиотека net/http включает полный URL в текст сетевой ошибки,
// а токен передаётся именно в query-строке. Без этой обёртки токен утёк бы
// в логи приложения при первом же обрыве соединения.
type redactedError struct {
	err    error
	secret string
}

func (e *redactedError) Error() string {
	msg := e.err.Error()
	if e.secret != "" {
		msg = strings.ReplaceAll(msg, e.secret, "***")
	}
	return msg
}

func (e *redactedError) Unwrap() error { return e.err }
