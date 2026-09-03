// Команда fakepam поднимает имитацию AAPM REST API Kron PAM для локальной
// отладки: отвечает тем же JSON, что и настоящий сервер.
//
//	fakepam -addr :8443 -tls -token 00000000-0000-0000-0000-000000000001
//
// Доступные записи выводятся при старте.
package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"flag"
	"fmt"
	"log"
	"math/big"
	"net"
	"net/http"
	"os"
	"time"

	"github.com/akprof2000/pam-client/pam"
	"github.com/akprof2000/pam-client/pam/mockpam"
)

// version подставляется при сборке через -ldflags.
var version = "dev"

func main() {
	addr := flag.String("addr", ":8443", "адрес прослушивания")
	token := flag.String("token", "00000000-0000-0000-0000-000000000001", "ожидаемый токен (пусто — не проверять)")
	useTLS := flag.Bool("tls", true, "включить HTTPS с самоподписанным сертификатом")
	certOut := flag.String("cert-out", "", "сохранить самоподписанный сертификат в файл (PEM) для -ca у pamget")
	flag.Parse()

	h := mockpam.NewHandler(*token, mockpam.DemoAccounts()...)
	// Регистрируем оба эндпоинта настоящего API: выдачу секрета и список записей.
	mux := http.NewServeMux()
	mux.Handle(pam.DefaultPath, logging(h))
	mux.Handle(pam.ListPath, logging(http.HandlerFunc(h.ListHandler)))

	// Сначала занимаем порт и только потом пишем файл сертификата: иначе при
	// «порт уже занят» на диске остался бы сертификат от неработающего сервера,
	// и клиент доверял бы не тому серверу.
	ln, err := net.Listen("tcp", *addr)
	if err != nil {
		log.Fatalf("не удалось занять адрес %s: %v", *addr, err)
	}

	scheme := "http"
	srv := &http.Server{Handler: mux, ReadHeaderTimeout: 10 * time.Second}
	if *useTLS {
		scheme = "https"
		cert, certPEMBytes, err := selfSignedCert()
		if err != nil {
			log.Fatalf("сертификат: %v", err)
		}
		srv.TLSConfig = &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12}
		if *certOut != "" {
			if err := os.WriteFile(*certOut, certPEMBytes, 0o644); err != nil {
				log.Fatalf("запись сертификата: %v", err)
			}
			log.Printf("сертификат сохранён в %s", *certOut)
		}
	}

	log.Printf("fakepam %s", version)
	log.Printf("имитация PAM слушает %s://%s%s", scheme, *addr, pam.DefaultPath)
	log.Printf("токен: %s", *token)
	for _, a := range mockpam.DemoAccounts() {
		log.Printf("  запись: %s", a.FullPath())
	}

	if *useTLS {
		err = srv.ServeTLS(ln, "", "")
	} else {
		err = srv.Serve(ln)
	}
	if err != nil {
		log.Fatal(err)
	}
}

func logging(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		log.Printf("%s %s account=%s/%s comment=%q", r.Method, r.URL.Path,
			q.Get("sapmAccountPath"), q.Get("sapmAccountName"), q.Get("comment"))
		next.ServeHTTP(w, r)
	})
}

// selfSignedCert выпускает сертификат на localhost/127.0.0.1 на сутки.
func selfSignedCert() (tls.Certificate, []byte, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, nil, err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return tls.Certificate{}, nil, err
	}
	tmpl := x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "fakepam"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
		DNSNames:              []string{"localhost"},
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1")},
	}
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &key.PublicKey, key)
	if err != nil {
		return tls.Certificate{}, nil, err
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return tls.Certificate{}, nil, err
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return tls.Certificate{}, nil, fmt.Errorf("сборка пары ключей: %w", err)
	}
	return cert, certPEM, nil
}
