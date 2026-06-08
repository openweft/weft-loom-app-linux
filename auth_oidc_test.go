package main

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestNewPKCEMeetsRFC7636(t *testing.T) {
	p, err := newPKCE()
	if err != nil {
		t.Fatal(err)
	}
	if len(p.Verifier) < 43 || len(p.Verifier) > 128 {
		t.Fatalf("verifier length %d not in 43..128", len(p.Verifier))
	}
	for _, r := range p.Verifier {
		if !((r >= 'A' && r <= 'Z') || (r >= 'a' && r <= 'z') ||
			(r >= '0' && r <= '9') || r == '-' || r == '.' || r == '_' || r == '~') {
			t.Fatalf("verifier has non-unreserved char %q", r)
		}
	}
	// challenge == base64url(sha256(verifier))
	sum := sha256.Sum256([]byte(p.Verifier))
	want := base64.RawURLEncoding.EncodeToString(sum[:])
	if p.Challenge != want {
		t.Fatalf("challenge mismatch:\ngot  %q\nwant %q", p.Challenge, want)
	}
	if p.Method != "S256" {
		t.Fatalf("method = %q, want S256", p.Method)
	}
}

func TestNewPKCEUniqueness(t *testing.T) {
	seen := map[string]struct{}{}
	for i := 0; i < 50; i++ {
		p, err := newPKCE()
		if err != nil {
			t.Fatal(err)
		}
		if _, dup := seen[p.Verifier]; dup {
			t.Fatalf("duplicate verifier on iteration %d", i)
		}
		seen[p.Verifier] = struct{}{}
	}
}

func TestNewStateNonEmpty(t *testing.T) {
	s, err := newState()
	if err != nil {
		t.Fatal(err)
	}
	if len(s) < 32 {
		t.Fatalf("state too short: %q", s)
	}
}

func TestEnsureOpenID(t *testing.T) {
	if got := ensureOpenID(nil); len(got) != 1 || got[0] != "openid" {
		t.Fatalf("nil input: %v", got)
	}
	if got := ensureOpenID([]string{"profile"}); got[0] != "openid" || len(got) != 2 {
		t.Fatalf("prepend missing: %v", got)
	}
	in := []string{"openid", "profile"}
	if got := ensureOpenID(in); len(got) != 2 || got[0] != "openid" {
		t.Fatalf("already-present mangled: %v", got)
	}
}

func TestValidateOIDCConfig(t *testing.T) {
	cases := []struct {
		name string
		cfg  OIDCConfig
		ok   bool
	}{
		{"missing-issuer", OIDCConfig{ClientID: "c", RedirectURI: "http://x/c"}, false},
		{"missing-client", OIDCConfig{Issuer: "https://i", RedirectURI: "http://x/c"}, false},
		{"missing-redirect", OIDCConfig{Issuer: "https://i", ClientID: "c"}, false},
		{"good", OIDCConfig{Issuer: "https://i", ClientID: "c", RedirectURI: "http://127.0.0.1:1/c"}, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			err := validateOIDCConfig(c.cfg)
			if (err == nil) != c.ok {
				t.Fatalf("got err=%v, want ok=%v", err, c.ok)
			}
		})
	}
}

func TestBuildAuthzURLContainsAllParams(t *testing.T) {
	pkce := pkcePair{Verifier: "v", Challenge: "ch", Method: "S256"}
	u, err := buildAuthzURL("https://idp.example/authorize?prompt=login",
		OIDCConfig{ClientID: "myclient", RedirectURI: "http://127.0.0.1:1/cb"},
		pkce, "stateXYZ", "openid profile")
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := url.Parse(u)
	if err != nil {
		t.Fatal(err)
	}
	q := parsed.Query()
	for k, want := range map[string]string{
		"response_type":         "code",
		"client_id":             "myclient",
		"redirect_uri":          "http://127.0.0.1:1/cb",
		"scope":                 "openid profile",
		"state":                 "stateXYZ",
		"code_challenge":        "ch",
		"code_challenge_method": "S256",
		"prompt":                "login", // preserved from base
	} {
		if got := q.Get(k); got != want {
			t.Fatalf("param %s = %q, want %q", k, got, want)
		}
	}
}

func TestBuildAuthzURLBadEndpoint(t *testing.T) {
	_, err := buildAuthzURL("://nope", OIDCConfig{}, pkcePair{}, "s", "openid")
	if err == nil {
		t.Fatal("expected parse error")
	}
}

// fakeIssuer is a minimal /.well-known + /token + /authorize triplet
// the test can drive the PKCE round through end-to-end.
type fakeIssuer struct {
	srv          *httptest.Server
	mu           sync.Mutex
	lastTokenReq url.Values
	codeToReturn string
	tokenStatus  int
	tokenBody    []byte
}

func newFakeIssuer(t *testing.T) *fakeIssuer {
	t.Helper()
	f := &fakeIssuer{codeToReturn: "fake-code", tokenStatus: 200}
	mux := http.NewServeMux()
	f.srv = httptest.NewServer(mux)

	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(providerMetadata{
			Issuer:                f.srv.URL,
			AuthorizationEndpoint: f.srv.URL + "/authorize",
			TokenEndpoint:         f.srv.URL + "/token",
		})
	})
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		f.mu.Lock()
		f.lastTokenReq = r.PostForm
		status := f.tokenStatus
		body := f.tokenBody
		f.mu.Unlock()
		if body == nil {
			body, _ = json.Marshal(tokenResponse{
				AccessToken: "at", IDToken: "idtok", TokenType: "Bearer", ExpiresIn: 3600,
			})
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_, _ = w.Write(body)
	})
	t.Cleanup(f.srv.Close)
	return f
}

func TestStartOIDCAndFinish(t *testing.T) {
	f := newFakeIssuer(t)
	cfg := OIDCConfig{
		Issuer:      f.srv.URL,
		ClientID:    "client-x",
		RedirectURI: "http://127.0.0.1:43219/callback",
		Scopes:      []string{"profile", "email"},
	}
	r, err := startOIDC(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(r.AuthorizeURL(), "code_challenge=") {
		t.Fatalf("authorize url missing PKCE challenge: %s", r.AuthorizeURL())
	}
	// Build a synthetic callback URL the WebView would have hit.
	cb := cfg.RedirectURI + "?code=fake-code&state=" + r.State()
	tok, err := r.Finish(context.Background(), cb)
	if err != nil {
		t.Fatal(err)
	}
	if tok.IDToken != "idtok" || tok.AccessToken != "at" {
		t.Fatalf("bad token: %+v", tok)
	}
	if tok.Kind != TokenOIDC {
		t.Fatalf("token kind = %v, want OIDC", tok.Kind)
	}
	if tok.ExpiresAt.IsZero() || time.Until(tok.ExpiresAt) <= 0 {
		t.Fatalf("expiry not set: %v", tok.ExpiresAt)
	}
	// token endpoint saw the PKCE verifier + code.
	f.mu.Lock()
	if got := f.lastTokenReq.Get("code_verifier"); got != r.pkce.Verifier {
		t.Errorf("token req verifier mismatch: got %q want %q", got, r.pkce.Verifier)
	}
	if got := f.lastTokenReq.Get("grant_type"); got != "authorization_code" {
		t.Errorf("grant_type = %q", got)
	}
	if got := f.lastTokenReq.Get("code"); got != "fake-code" {
		t.Errorf("code = %q", got)
	}
	if got := f.lastTokenReq.Get("client_id"); got != "client-x" {
		t.Errorf("client_id = %q", got)
	}
	f.mu.Unlock()
}

func TestFinishRejectsStateMismatch(t *testing.T) {
	f := newFakeIssuer(t)
	r, err := startOIDC(context.Background(), OIDCConfig{
		Issuer: f.srv.URL, ClientID: "c", RedirectURI: "http://127.0.0.1:1/cb",
	})
	if err != nil {
		t.Fatal(err)
	}
	cb := "http://127.0.0.1:1/cb?code=ok&state=NOT-THE-RIGHT-STATE"
	if _, err := r.Finish(context.Background(), cb); err == nil {
		t.Fatal("expected state mismatch error")
	}
}

func TestFinishSurfacesProviderError(t *testing.T) {
	f := newFakeIssuer(t)
	r, _ := startOIDC(context.Background(), OIDCConfig{
		Issuer: f.srv.URL, ClientID: "c", RedirectURI: "http://127.0.0.1:1/cb",
	})
	cb := "http://127.0.0.1:1/cb?error=access_denied&error_description=user+said+no&state=" + r.State()
	_, err := r.Finish(context.Background(), cb)
	if err == nil {
		t.Fatal("expected error")
	}
	if !strings.Contains(err.Error(), "access_denied") {
		t.Fatalf("error did not include code: %v", err)
	}
}

func TestFinishMissingCode(t *testing.T) {
	f := newFakeIssuer(t)
	r, _ := startOIDC(context.Background(), OIDCConfig{
		Issuer: f.srv.URL, ClientID: "c", RedirectURI: "http://127.0.0.1:1/cb",
	})
	cb := "http://127.0.0.1:1/cb?state=" + r.State()
	if _, err := r.Finish(context.Background(), cb); err == nil {
		t.Fatal("expected missing-code error")
	}
}

func TestFinishTokenEndpointFailure(t *testing.T) {
	f := newFakeIssuer(t)
	f.mu.Lock()
	f.tokenStatus = 400
	f.tokenBody = []byte(`{"error":"invalid_grant"}`)
	f.mu.Unlock()
	r, _ := startOIDC(context.Background(), OIDCConfig{
		Issuer: f.srv.URL, ClientID: "c", RedirectURI: "http://127.0.0.1:1/cb",
	})
	cb := "http://127.0.0.1:1/cb?code=x&state=" + r.State()
	if _, err := r.Finish(context.Background(), cb); err == nil {
		t.Fatal("expected token endpoint error")
	}
}

func TestDiscoverOIDCMissingEndpoints(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"issuer":"https://x"}`))
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()
	_, err := discoverOIDC(context.Background(), http.DefaultClient, srv.URL)
	if err == nil {
		t.Fatal("expected missing-endpoints error")
	}
}

func TestDiscoverOIDCBadStatus(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(500)
	}))
	defer srv.Close()
	if _, err := discoverOIDC(context.Background(), http.DefaultClient, srv.URL); err == nil {
		t.Fatal("expected status error")
	}
}

func TestAwaitCallbackPropagatesURL(t *testing.T) {
	// Pick a free port, then re-use it in the redirect URI.
	const redirect = "http://127.0.0.1:43821/callback"
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	gotCh := make(chan string, 1)
	errCh := make(chan error, 1)
	go func() {
		s, err := awaitCallback(ctx, redirect, 2*time.Second)
		if err != nil {
			errCh <- err
			return
		}
		gotCh <- s
	}()

	// Wait briefly then poke the listener.
	deadline := time.Now().Add(2 * time.Second)
	var resp *http.Response
	var err error
	for time.Now().Before(deadline) {
		resp, err = http.Get(redirect + "?code=abc&state=xyz")
		if err == nil {
			resp.Body.Close()
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if err != nil {
		t.Fatalf("could not hit callback listener: %v", err)
	}

	select {
	case s := <-gotCh:
		if !strings.Contains(s, "code=abc") || !strings.Contains(s, "state=xyz") {
			t.Fatalf("callback url missing params: %s", s)
		}
	case err := <-errCh:
		t.Fatalf("awaitCallback err: %v", err)
	case <-time.After(2 * time.Second):
		t.Fatal("awaitCallback did not return")
	}
}
