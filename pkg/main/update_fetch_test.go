package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"strings"
	"testing"
	"time"

	"go.uber.org/zap"
)

// makeTestKeyCert returns a matching private key pem and self-signed certificate pem
func makeTestKeyCert(t *testing.T) (keyPem, certPem string) {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	keyDer, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	keyPem = string(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDer}))

	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	certDer, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	certPem = string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDer}))

	return keyPem, certPem
}

func TestSplitKeyAndCertChainPem(t *testing.T) {
	key := "-----BEGIN EC PRIVATE KEY-----\nabc\n-----END EC PRIVATE KEY-----\n"
	keyNoTrailingLF := strings.TrimSuffix(key, "\n")
	chain := "-----BEGIN CERTIFICATE-----\ndef\n-----END CERTIFICATE-----\n-----BEGIN CERTIFICATE-----\nghi\n-----END CERTIFICATE-----\n"

	tests := []struct {
		name     string
		combined string
		wantKey  string
		wantCert string
		wantErr  bool
	}{
		{"key with trailing LF + LF + chain", key + "\n" + chain, key, chain, false},
		{"key without trailing LF + LF + chain", keyNoTrailingLF + "\n" + chain, keyNoTrailingLF, chain, false},
		{"single cert", key + "\n" + strings.Split(chain, "-----BEGIN CERTIFICATE-----\nghi")[0], key, strings.Split(chain, "-----BEGIN CERTIFICATE-----\nghi")[0], false},
		{"chain only", chain, "", "", true},
		{"key only", key, "", "", true},
		{"empty", "", "", "", true},
		{"no separator", keyNoTrailingLF + chain, "", "", true},
		{"only separator before cert", "\n" + chain, "", "", true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			gotKey, gotCert, err := splitKeyAndCertChainPem([]byte(tc.combined))
			if tc.wantErr {
				if err == nil {
					t.Fatalf("expected error, got key=%q cert=%q", gotKey, gotCert)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %s", err)
			}
			if string(gotKey) != tc.wantKey {
				t.Errorf("key = %q, want %q", gotKey, tc.wantKey)
			}
			if string(gotCert) != tc.wantCert {
				t.Errorf("cert = %q, want %q", gotCert, tc.wantCert)
			}
		})
	}
}

func newFetchTestApp(serverURL string) *app {
	return &app{
		logger:          zap.NewNop().Sugar(),
		httpClient:      makeHttpClient(),
		shutdownContext: context.Background(),
		cfg: &config{
			ServerAddress: serverURL,
			Certs:         []certConfig{{CertName: "mycert", CertApiKey: "certkey", KeyApiKey: "keykey"}},
		},
		tlsCerts:          []*SafeCert{NewSafeCert()},
		pendingJobCancels: []context.CancelFunc{nil},
		pollETags:         []string{""},
	}
}

func TestUpdateClientKeyAndCertchain(t *testing.T) {
	keyA, certA := makeTestKeyCert(t)
	bodyA := keyA + "\n" + certA

	s := newPemTestServer(bodyA, "certkey.keykey", true)
	defer s.srv.Close()
	app := newFetchTestApp(s.srv.URL)

	// 1: first fetch loads the pair into memory and remembers the etag
	updated, err := app.updateClientKeyAndCertchain(0)
	if err != nil {
		t.Fatalf("first fetch failed: %s", err)
	}
	if !updated {
		t.Fatal("first fetch must report updated")
	}
	if k, c := app.tlsCerts[0].Read(); string(k) != keyA || string(c) != certA {
		t.Fatal("memory does not hold the exact key/cert pem from the server")
	}
	if app.pollETags[0] != etagOf(bodyA) {
		t.Fatalf("etag not remembered: %q", app.pollETags[0])
	}
	if got := s.request(0).URL.Path; got != "/certwarden/api/v1/download/privatecertchains/mycert" {
		t.Fatalf("unexpected request path %q", got)
	}

	// 2: second fetch is conditional and results in 304 / not updated
	updated, err = app.updateClientKeyAndCertchain(0)
	if err != nil {
		t.Fatalf("second fetch failed: %s", err)
	}
	if updated {
		t.Fatal("second fetch must not report updated")
	}
	if got := s.request(1).Header.Get("If-None-Match"); got != etagOf(bodyA) {
		t.Fatalf("second fetch If-None-Match = %q, want %q", got, etagOf(bodyA))
	}

	// 3: server has a new pair -> updated, new etag remembered
	keyB, certB := makeTestKeyCert(t)
	bodyB := keyB + "\n" + certB
	s.setBody(bodyB)
	updated, err = app.updateClientKeyAndCertchain(0)
	if err != nil {
		t.Fatalf("third fetch failed: %s", err)
	}
	if !updated {
		t.Fatal("third fetch must report updated")
	}
	if k, c := app.tlsCerts[0].Read(); string(k) != keyB || string(c) != certB {
		t.Fatal("memory does not hold the new key/cert pem")
	}
	if app.pollETags[0] != etagOf(bodyB) {
		t.Fatalf("new etag not remembered: %q", app.pollETags[0])
	}

	// 4: server returns a mismatched pair -> error, memory and etag untouched
	s.setBody(keyA + "\n" + certB)
	updated, err = app.updateClientKeyAndCertchain(0)
	if err == nil || updated {
		t.Fatalf("mismatched pair must fail, got updated=%t err=%v", updated, err)
	}
	if k, c := app.tlsCerts[0].Read(); string(k) != keyB || string(c) != certB {
		t.Fatal("memory must be untouched after a mismatched pair")
	}
	if app.pollETags[0] != etagOf(bodyB) {
		t.Fatalf("etag must be untouched after a mismatched pair, got %q", app.pollETags[0])
	}

	// 5: wrong api key -> error with a hint about the api key vars
	app.cfg.Certs[0].KeyApiKey = "wrong"
	_, err = app.updateClientKeyAndCertchain(0)
	if err == nil || !strings.Contains(err.Error(), "KEY_APIKEY") {
		t.Fatalf("expected unauthorized error with KEY_APIKEY hint, got %v", err)
	}
}
