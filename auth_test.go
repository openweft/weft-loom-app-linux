package main

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

func TestTokenBearerPrefersIDToken(t *testing.T) {
	tok := Token{IDToken: "id", AccessToken: "ac"}
	if got := tok.Bearer(); got != "id" {
		t.Fatalf("Bearer() = %q, want id", got)
	}
	tok = Token{AccessToken: "ac"}
	if got := tok.Bearer(); got != "ac" {
		t.Fatalf("Bearer() fallback = %q", got)
	}
}

func TestTokenExpired(t *testing.T) {
	if (Token{}).Expired() {
		t.Fatal("zero expiry should be treated as 'no expiry'")
	}
	past := Token{ExpiresAt: time.Now().Add(-time.Hour)}
	if !past.Expired() {
		t.Fatal("past token should be expired")
	}
	future := Token{ExpiresAt: time.Now().Add(time.Hour)}
	if future.Expired() {
		t.Fatal("future token should not be expired")
	}
	// 30s skew : a token expiring in 5s is treated as expired.
	soon := Token{ExpiresAt: time.Now().Add(5 * time.Second)}
	if !soon.Expired() {
		t.Fatal("near-expiry token should be marked expired (skew)")
	}
}

func TestAuthConfigEnabled(t *testing.T) {
	if (AuthConfig{}).Enabled() {
		t.Fatal("zero AuthConfig must not be Enabled")
	}
	if !(AuthConfig{Issuer: "https://i", ClientID: "c"}).Enabled() {
		t.Fatal("complete AuthConfig must be Enabled")
	}
	if (AuthConfig{Issuer: "https://i"}).Enabled() {
		t.Fatal("issuer alone is not Enabled (no client_id)")
	}
}

func TestLoadAuthConfigMissingFile(t *testing.T) {
	cfg, err := LoadAuthConfig(filepath.Join(t.TempDir(), "no-such.json"))
	if err != nil {
		t.Fatalf("missing file should not be an error, got %v", err)
	}
	if cfg.Enabled() {
		t.Fatal("missing file should yield zero AuthConfig")
	}
}

func TestLoadAuthConfigNoAuthBlock(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "app.json")
	if err := os.WriteFile(path, []byte(`{"endpoints":[]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := LoadAuthConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Enabled() {
		t.Fatal("absent auth block should yield zero AuthConfig")
	}
}

func TestLoadAuthConfigWithBlock(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "app.json")
	body := `{"auth":{"issuer":"https://dex.weft.local/dex","client_id":"weft-app-osx",` +
		`"scopes":["openid","profile"],"redirect_uri":"http://127.0.0.1:43219/callback"}}`
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := LoadAuthConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	if !cfg.Enabled() {
		t.Fatal("should be enabled")
	}
	if cfg.KeychainService != "weft-app" {
		t.Fatalf("default service = %q", cfg.KeychainService)
	}
	if cfg.KeychainAccount != "https://dex.weft.local/dex" {
		t.Fatalf("default account = %q", cfg.KeychainAccount)
	}
}

// --- Authenticate orchestration tests using in-memory doubles --------

type memKC struct {
	mu sync.Mutex
	m  map[string]Token
}

func (m *memKC) key(s, a string) string { return s + "\x00" + a }
func (m *memKC) Get(s, a string) (Token, bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.m == nil {
		return Token{}, false, nil
	}
	t, ok := m.m[m.key(s, a)]
	return t, ok, nil
}
func (m *memKC) Set(s, a string, t Token) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.m == nil {
		m.m = map[string]Token{}
	}
	m.m[m.key(s, a)] = t
	return nil
}
func (m *memKC) Delete(s, a string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.m, m.key(s, a))
	return nil
}

type stubPicker struct {
	choice          AuthChoice
	pickErr         error
	returnURL       string
	openErr         error
	sawOfferKeypair bool
}

func (s *stubPicker) Pick(ctx context.Context, offerKeypair bool) AuthChoice {
	s.sawOfferKeypair = offerKeypair
	return s.choice
}
func (s *stubPicker) OpenAuthWebView(ctx context.Context, u, redir string) (string, error) {
	if s.openErr != nil {
		return "", s.openErr
	}
	return s.returnURL, nil
}

func TestAuthenticateNotEnabledShortCircuits(t *testing.T) {
	tok, err := Authenticate(context.Background(), AuthConfig{}, &memKC{}, &stubPicker{})
	if err != nil {
		t.Fatal(err)
	}
	if tok.Bearer() != "" {
		t.Fatal("disabled auth must return zero Token")
	}
}

func TestAuthenticateUsesCache(t *testing.T) {
	cfg := AuthConfig{
		Issuer: "https://i", ClientID: "c",
		KeychainService: "svc", KeychainAccount: "acct",
	}
	kc := &memKC{}
	cached := Token{
		Kind: TokenOIDC, IDToken: "cached",
		ExpiresAt: time.Now().Add(time.Hour),
	}
	_ = kc.Set(cfg.KeychainService, cfg.KeychainAccount, cached)

	tok, err := Authenticate(context.Background(), cfg, kc,
		&stubPicker{choice: ChoiceCancelled}) // picker would fail if called
	if err != nil {
		t.Fatal(err)
	}
	if tok.IDToken != "cached" {
		t.Fatalf("expected cached token, got %+v", tok)
	}
}

func TestAuthenticateExpiredCacheTriggersPicker(t *testing.T) {
	cfg := AuthConfig{Issuer: "https://i", ClientID: "c",
		KeychainService: "svc", KeychainAccount: "acct"}
	kc := &memKC{}
	_ = kc.Set(cfg.KeychainService, cfg.KeychainAccount, Token{
		Kind: TokenOIDC, IDToken: "old", ExpiresAt: time.Now().Add(-time.Hour),
	})
	// Picker reports Cancelled ; orchestrator must surface the cancel.
	_, err := Authenticate(context.Background(), cfg, kc, &stubPicker{choice: ChoiceCancelled})
	if err == nil {
		t.Fatal("expected dismissed error")
	}
}

func TestTokenJSONRoundTrip(t *testing.T) {
	want := Token{
		Kind: TokenOIDC, IDToken: "id", AccessToken: "ac",
		Issuer: "https://i", IssuedAt: time.Now().UTC().Truncate(time.Second),
		ExpiresAt: time.Now().UTC().Add(time.Hour).Truncate(time.Second),
	}
	b, err := json.Marshal(want)
	if err != nil {
		t.Fatal(err)
	}
	var got Token
	if err := json.Unmarshal(b, &got); err != nil {
		t.Fatal(err)
	}
	if got.IDToken != want.IDToken || got.Kind != want.Kind ||
		!got.ExpiresAt.Equal(want.ExpiresAt) {
		t.Fatalf("round-trip mismatch:\nwant %+v\ngot  %+v", want, got)
	}
}

func TestRunOpenPubkeyReturnsSentinel(t *testing.T) {
	_, err := runOpenPubkey(context.Background(), AuthConfig{Issuer: "https://i"}, &stubPicker{})
	if !errors.Is(err, ErrOpenPubkeyUnsupported) {
		t.Fatalf("want sentinel, got %v", err)
	}
}
