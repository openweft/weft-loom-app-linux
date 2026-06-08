package main

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	corauth "github.com/openweft/weft-app-core/auth"
)

// memKeypair is an in-process KeypairStore double for unit tests.
type memKeypair struct {
	mu sync.Mutex
	m  map[string]ed25519.PrivateKey
}

func (m *memKeypair) key(s, a string) string { return s + "\x00" + a }
func (m *memKeypair) Get(s, a string) (ed25519.PrivateKey, bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.m == nil {
		return nil, false, nil
	}
	v, ok := m.m[m.key(s, a)]
	return v, ok, nil
}
func (m *memKeypair) Set(s, a string, p ed25519.PrivateKey) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.m == nil {
		m.m = map[string]ed25519.PrivateKey{}
	}
	m.m[m.key(s, a)] = p
	return nil
}
func (m *memKeypair) Delete(s, a string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.m, m.key(s, a))
	return nil
}

func TestKeypairAccountForFallsBackToDefault(t *testing.T) {
	if got := keypairAccountFor(AuthConfig{}); got != "default" {
		t.Fatalf("empty issuer should default to 'default', got %q", got)
	}
	if got := keypairAccountFor(AuthConfig{Issuer: "https://i"}); got != "https://i" {
		t.Fatalf("non-empty issuer should pass through, got %q", got)
	}
}

func TestLoadOrCreateKeypairGeneratesOnMiss(t *testing.T) {
	store := &memKeypair{}
	priv, pub, fresh, err := loadOrCreateKeypair(store, "acct")
	if err != nil {
		t.Fatal(err)
	}
	if !fresh {
		t.Fatal("first call must report fresh=true")
	}
	if len(priv) != ed25519.PrivateKeySize {
		t.Fatalf("priv length = %d, want %d", len(priv), ed25519.PrivateKeySize)
	}
	if len(pub) != ed25519.PublicKeySize {
		t.Fatalf("pub length = %d, want %d", len(pub), ed25519.PublicKeySize)
	}

	// Second call must reuse the persisted key.
	priv2, pub2, fresh2, err := loadOrCreateKeypair(store, "acct")
	if err != nil {
		t.Fatal(err)
	}
	if fresh2 {
		t.Fatal("second call must report fresh=false")
	}
	if string(priv2) != string(priv) || string(pub2) != string(pub) {
		t.Fatal("second call must return the same keypair")
	}
}

type errStore struct{ err error }

func (e errStore) Get(string, string) (ed25519.PrivateKey, bool, error) {
	return nil, false, e.err
}
func (e errStore) Set(string, string, ed25519.PrivateKey) error { return e.err }
func (e errStore) Delete(string, string) error                  { return e.err }

func TestLoadOrCreateKeypairPropagatesGetError(t *testing.T) {
	_, _, _, err := loadOrCreateKeypair(errStore{err: errors.New("boom")}, "acct")
	if err == nil {
		t.Fatal("get error must surface")
	}
}

func TestPostKeypairAssertionHappyPath(t *testing.T) {
	priv, _, _ := corauth.GenerateKeypair()
	var capturedBody []byte
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("method = %s, want POST", r.Method)
		}
		if ct := r.Header.Get("Content-Type"); !strings.HasPrefix(ct, "application/jose") {
			t.Errorf("content-type = %q, want application/jose*", ct)
		}
		capturedBody, _ = io.ReadAll(r.Body)
		_ = json.NewEncoder(w).Encode(keypairResponse{
			IDToken:       "dev-jwt.xxx.yyy",
			Kind:          "keypair",
			ExpiresAtUnix: 9999999999,
		})
	}))
	defer srv.Close()

	endpoint := srv.URL + "/api/auth/keypair"
	jws, err := corauth.SignAssertion(priv, endpoint)
	if err != nil {
		t.Fatal(err)
	}
	tok, err := postKeypairAssertion(context.Background(), srv.Client(), endpoint, jws)
	if err != nil {
		t.Fatal(err)
	}
	if tok.Kind != TokenKindKeypair {
		t.Fatalf("kind = %s, want keypair", tok.Kind)
	}
	if tok.IDToken == "" {
		t.Fatal("id_token must be populated")
	}
	if tok.ExpiresAt.IsZero() {
		t.Fatal("expires_at must be set when server returned expires_at_unix")
	}
	if string(capturedBody) != string(jws) {
		t.Fatal("server must receive the JWS verbatim")
	}
}

func TestPostKeypairAssertion404SurfacesDisabledHint(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()
	priv, _, _ := corauth.GenerateKeypair()
	jws, _ := corauth.SignAssertion(priv, srv.URL+"/api/auth/keypair")
	_, err := postKeypairAssertion(context.Background(), srv.Client(), srv.URL+"/api/auth/keypair", jws)
	if err == nil || !strings.Contains(err.Error(), "disabled") {
		t.Fatalf("404 must surface a 'disabled' hint, got %v", err)
	}
}

func TestPostKeypairAssertionNon200ReturnsErrorBody(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte("pubkey not allowlisted"))
	}))
	defer srv.Close()
	priv, _, _ := corauth.GenerateKeypair()
	jws, _ := corauth.SignAssertion(priv, srv.URL+"/api/auth/keypair")
	_, err := postKeypairAssertion(context.Background(), srv.Client(), srv.URL+"/api/auth/keypair", jws)
	if err == nil || !strings.Contains(err.Error(), "401") || !strings.Contains(err.Error(), "allowlist") {
		t.Fatalf("non-200 must surface status + body, got %v", err)
	}
}

func TestPostKeypairAssertionEmptyIDTokenRejected(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(keypairResponse{Kind: "keypair"})
	}))
	defer srv.Close()
	priv, _, _ := corauth.GenerateKeypair()
	jws, _ := corauth.SignAssertion(priv, srv.URL+"/api/auth/keypair")
	_, err := postKeypairAssertion(context.Background(), srv.Client(), srv.URL+"/api/auth/keypair", jws)
	if err == nil || !strings.Contains(err.Error(), "no id_token") {
		t.Fatalf("missing id_token must error, got %v", err)
	}
}

func TestRunKeypairRequiresGateway(t *testing.T) {
	_, err := runKeypair(context.Background(), AuthConfig{KeypairFallback: true})
	if err == nil || !strings.Contains(err.Error(), "gateway") {
		t.Fatalf("empty gateway must error, got %v", err)
	}
}
