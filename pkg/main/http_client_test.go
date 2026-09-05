package main

import (
	"context"
	"crypto/sha1"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"go.uber.org/zap"
)

const testPem = "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n"

// pemTestServer mimics the Cert Warden server download endpoints: it writes the pem with
// http.ServeContent, optionally with an ETag (sha1 of the content) like the real server
type pemTestServer struct {
	mu       sync.Mutex
	body     string
	withETag bool
	apiKey   string
	reqs     []*http.Request
	srv      *httptest.Server
}

func newPemTestServer(body, apiKey string, withETag bool) *pemTestServer {
	s := &pemTestServer{body: body, withETag: withETag, apiKey: apiKey}
	s.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.mu.Lock()
		defer s.mu.Unlock()

		s.reqs = append(s.reqs, r.Clone(context.Background()))

		if r.Header.Get("apiKey") != s.apiKey {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}

		w.Header().Set("Content-Type", "application/x-pem-file")
		if s.withETag {
			w.Header().Set("ETag", etagOf(s.body))
		}
		w.Header().Set("Cache-Control", "no-store")

		http.ServeContent(w, r, "test.pem", time.Time{}, strings.NewReader(s.body))
	}))
	return s
}

func (s *pemTestServer) setBody(body string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.body = body
}

func (s *pemTestServer) request(i int) *http.Request {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.reqs[i]
}

func (s *pemTestServer) requestCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.reqs)
}

// etagOf returns the ETag the Cert Warden server would send for content
func etagOf(content string) string {
	return fmt.Sprintf("\"%x\"", sha1.Sum([]byte(content)))
}

func newTestApp() *app {
	return &app{
		logger:          zap.NewNop().Sugar(),
		httpClient:      makeHttpClient(),
		shutdownContext: context.Background(),
	}
}

func TestGetPemWithApiKeyConditional(t *testing.T) {
	s := newPemTestServer(testPem, "secret", true)
	defer s.srv.Close()
	app := newTestApp()

	// first request: no etag known -> 200 with body and etag
	pemContent, etag, notModified, err := app.getPemWithApiKey(context.Background(), s.srv.URL, "secret", "")
	if err != nil {
		t.Fatalf("first request failed: %s", err)
	}
	if notModified {
		t.Fatal("first request must not be notModified")
	}
	if string(pemContent) != testPem {
		t.Fatalf("unexpected pem content: %q", pemContent)
	}
	if etag != etagOf(testPem) {
		t.Fatalf("unexpected etag %q, want %q", etag, etagOf(testPem))
	}
	if got := s.request(0).Header.Get("If-None-Match"); got != "" {
		t.Fatalf("first request must not send If-None-Match, got %q", got)
	}

	// second request with the etag -> 304, no body, same etag
	pemContent, etag2, notModified, err := app.getPemWithApiKey(context.Background(), s.srv.URL, "secret", etag)
	if err != nil {
		t.Fatalf("second request failed: %s", err)
	}
	if !notModified {
		t.Fatal("second request must be notModified")
	}
	if pemContent != nil {
		t.Fatalf("notModified must return nil content, got %q", pemContent)
	}
	if etag2 != etag {
		t.Fatalf("notModified must return the sent etag, got %q", etag2)
	}
	// the etag must be sent verbatim (quoted), otherwise the server never answers 304
	if got := s.request(1).Header.Get("If-None-Match"); got != etag {
		t.Fatalf("If-None-Match sent as %q, want %q", got, etag)
	}

	// content changes on server -> 200 with new body and new etag
	newPem := "-----BEGIN CERTIFICATE-----\nMIIC\n-----END CERTIFICATE-----\n"
	s.setBody(newPem)
	pemContent, etag3, notModified, err := app.getPemWithApiKey(context.Background(), s.srv.URL, "secret", etag)
	if err != nil {
		t.Fatalf("third request failed: %s", err)
	}
	if notModified {
		t.Fatal("third request must not be notModified")
	}
	if string(pemContent) != newPem {
		t.Fatalf("unexpected pem content: %q", pemContent)
	}
	if etag3 != etagOf(newPem) {
		t.Fatalf("unexpected etag %q, want %q", etag3, etagOf(newPem))
	}
}

func TestGetPemWithApiKeyServerWithoutETag(t *testing.T) {
	s := newPemTestServer(testPem, "secret", false)
	defer s.srv.Close()
	app := newTestApp()

	// server without etag: 200 with body, blank etag
	pemContent, etag, notModified, err := app.getPemWithApiKey(context.Background(), s.srv.URL, "secret", "")
	if err != nil {
		t.Fatalf("request failed: %s", err)
	}
	if notModified || string(pemContent) != testPem || etag != "" {
		t.Fatalf("unexpected result: notModified=%t etag=%q content=%q", notModified, etag, pemContent)
	}

	// a stale etag sent to a server without etag support must still yield 200 with body
	pemContent, etag, notModified, err = app.getPemWithApiKey(context.Background(), s.srv.URL, "secret", "\"stale\"")
	if err != nil {
		t.Fatalf("request failed: %s", err)
	}
	if notModified || string(pemContent) != testPem || etag != "" {
		t.Fatalf("unexpected result: notModified=%t etag=%q content=%q", notModified, etag, pemContent)
	}
}

func TestGetPemWithApiKeyUnauthorized(t *testing.T) {
	s := newPemTestServer(testPem, "secret", true)
	defer s.srv.Close()
	app := newTestApp()

	_, _, _, err := app.getPemWithApiKey(context.Background(), s.srv.URL, "wrong", "")
	var statusErr *httpStatusError
	if !errors.As(err, &statusErr) || statusErr.status != http.StatusUnauthorized {
		t.Fatalf("expected httpStatusError 401, got %v", err)
	}
}

func TestGetPemWithApiKeyNotPem(t *testing.T) {
	s := newPemTestServer("this is not pem", "secret", true)
	defer s.srv.Close()
	app := newTestApp()

	_, _, _, err := app.getPemWithApiKey(context.Background(), s.srv.URL, "secret", "")
	if err == nil {
		t.Fatal("expected error for non-pem body")
	}
}

func TestGetPemWithApiKeyCanceledContext(t *testing.T) {
	s := newPemTestServer(testPem, "secret", true)
	defer s.srv.Close()
	app := newTestApp()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, _, _, err := app.getPemWithApiKey(ctx, s.srv.URL, "secret", "")
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context.Canceled, got %v", err)
	}
	if s.requestCount() != 0 {
		t.Fatalf("expected no request to reach the server, got %d", s.requestCount())
	}
}
