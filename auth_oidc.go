package main

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// auth_oidc.go : the OIDC Authorization Code + PKCE state machine.
//
// Pure Go : no Cocoa, no Keychain. The cgo Cocoa layer drives it by
// calling AuthorizeURL, opening that in a child WKWebView, then handing
// the redirect URL it sees back via FinishOIDC. The local HTTP callback
// listener is optional ; it lets us also support `redirect_uri =
// http://127.0.0.1:<port>/callback` flows (more idp-friendly) instead
// of intercepting the navigation in the WebView.

// OIDCConfig captures the discoverable OIDC provider settings the user
// configures in app.json.
type OIDCConfig struct {
	// Issuer base URL, e.g. "https://dex.weft.local/dex". The standard
	// /.well-known/openid-configuration document lives under it.
	Issuer string
	// ClientID registered with the issuer for this app.
	ClientID string
	// Scopes requested. Always includes "openid" ; "profile email groups"
	// are typical additions.
	Scopes []string
	// RedirectURI the issuer redirects back to. Typically
	// "http://127.0.0.1:<port>/callback".
	RedirectURI string
	// HTTPClient is injected for tests ; default = http.DefaultClient.
	HTTPClient *http.Client
}

// providerMetadata is the subset of /.well-known/openid-configuration
// we actually read.
type providerMetadata struct {
	AuthorizationEndpoint string `json:"authorization_endpoint"`
	TokenEndpoint         string `json:"token_endpoint"`
	JWKSURI               string `json:"jwks_uri"`
	Issuer                string `json:"issuer"`
}

// pkcePair carries the PKCE challenge / verifier for one auth round.
type pkcePair struct {
	Verifier  string // 43..128 url-safe chars (RFC 7636 §4.1)
	Challenge string // base64url(sha256(verifier))
	Method    string // "S256"
}

// newPKCE generates a fresh PKCE pair backed by 32 bytes of crypto
// randomness (44 base64url chars after padding-strip, well above the
// RFC 7636 minimum of 43).
func newPKCE() (pkcePair, error) {
	var buf [32]byte
	if _, err := rand.Read(buf[:]); err != nil {
		return pkcePair{}, fmt.Errorf("pkce: read entropy: %w", err)
	}
	verifier := base64.RawURLEncoding.EncodeToString(buf[:])
	sum := sha256.Sum256([]byte(verifier))
	challenge := base64.RawURLEncoding.EncodeToString(sum[:])
	return pkcePair{Verifier: verifier, Challenge: challenge, Method: "S256"}, nil
}

// newState returns a fresh 32-byte base64url state nonce, matched on
// callback to prevent CSRF on the redirect.
func newState() (string, error) {
	var buf [32]byte
	if _, err := rand.Read(buf[:]); err != nil {
		return "", fmt.Errorf("state: read entropy: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(buf[:]), nil
}

// oidcRound is one in-progress authorization. It owns the PKCE pair,
// the state nonce, and the discovered endpoint URLs.
type oidcRound struct {
	cfg      OIDCConfig
	meta     providerMetadata
	pkce     pkcePair
	state    string
	scopes   string
	authzURL string
}

// startOIDC discovers the issuer, generates PKCE + state, and builds
// the authorization URL the WKWebView should navigate to.
func startOIDC(ctx context.Context, cfg OIDCConfig) (*oidcRound, error) {
	if err := validateOIDCConfig(cfg); err != nil {
		return nil, err
	}
	hc := cfg.HTTPClient
	if hc == nil {
		hc = http.DefaultClient
	}
	meta, err := discoverOIDC(ctx, hc, cfg.Issuer)
	if err != nil {
		return nil, err
	}
	pkce, err := newPKCE()
	if err != nil {
		return nil, err
	}
	state, err := newState()
	if err != nil {
		return nil, err
	}
	scopes := strings.Join(ensureOpenID(cfg.Scopes), " ")
	authz, err := buildAuthzURL(meta.AuthorizationEndpoint, cfg, pkce, state, scopes)
	if err != nil {
		return nil, err
	}
	return &oidcRound{
		cfg:      cfg,
		meta:     meta,
		pkce:     pkce,
		state:    state,
		scopes:   scopes,
		authzURL: authz,
	}, nil
}

// AuthorizeURL is the URL the WKWebView should navigate to.
func (r *oidcRound) AuthorizeURL() string { return r.authzURL }

// State is the random nonce planted in the URL ; callbacks that don't
// match are rejected.
func (r *oidcRound) State() string { return r.state }

// Finish completes the round by validating the callback URL and
// exchanging the code for tokens.
func (r *oidcRound) Finish(ctx context.Context, callbackURL string) (Token, error) {
	u, err := url.Parse(callbackURL)
	if err != nil {
		return Token{}, fmt.Errorf("oidc: parse callback: %w", err)
	}
	q := u.Query()
	if e := q.Get("error"); e != "" {
		desc := q.Get("error_description")
		if desc != "" {
			return Token{}, fmt.Errorf("oidc: provider returned %s: %s", e, desc)
		}
		return Token{}, fmt.Errorf("oidc: provider returned %s", e)
	}
	if got := q.Get("state"); got != r.state {
		return Token{}, fmt.Errorf("oidc: state mismatch (csrf?) : got %q", got)
	}
	code := q.Get("code")
	if code == "" {
		return Token{}, errors.New("oidc: callback missing code")
	}
	return r.exchange(ctx, code)
}

// exchange POSTs the authorization code + PKCE verifier to the token
// endpoint.
func (r *oidcRound) exchange(ctx context.Context, code string) (Token, error) {
	form := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"redirect_uri":  {r.cfg.RedirectURI},
		"client_id":     {r.cfg.ClientID},
		"code_verifier": {r.pkce.Verifier},
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, r.meta.TokenEndpoint,
		strings.NewReader(form.Encode()))
	if err != nil {
		return Token{}, fmt.Errorf("oidc: build token request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")

	hc := r.cfg.HTTPClient
	if hc == nil {
		hc = http.DefaultClient
	}
	resp, err := hc.Do(req)
	if err != nil {
		return Token{}, fmt.Errorf("oidc: token request: %w", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode/100 != 2 {
		return Token{}, fmt.Errorf("oidc: token endpoint %d: %s", resp.StatusCode, string(body))
	}
	var tr tokenResponse
	if err := json.Unmarshal(body, &tr); err != nil {
		return Token{}, fmt.Errorf("oidc: decode token response: %w", err)
	}
	if tr.IDToken == "" && tr.AccessToken == "" {
		return Token{}, errors.New("oidc: token response had no usable token")
	}
	tok := Token{
		Kind:         TokenOIDC,
		IDToken:      tr.IDToken,
		AccessToken:  tr.AccessToken,
		RefreshToken: tr.RefreshToken,
		TokenType:    tr.TokenType,
		Issuer:       r.cfg.Issuer,
		IssuedAt:     time.Now().UTC(),
	}
	if tr.ExpiresIn > 0 {
		tok.ExpiresAt = tok.IssuedAt.Add(time.Duration(tr.ExpiresIn) * time.Second)
	}
	return tok, nil
}

// tokenResponse is the relevant subset of RFC 6749 §5.1 token responses
// plus the OIDC id_token addition.
type tokenResponse struct {
	AccessToken  string `json:"access_token"`
	IDToken      string `json:"id_token"`
	RefreshToken string `json:"refresh_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int64  `json:"expires_in"`
}

// validateOIDCConfig ensures the user actually configured the bits
// required to run the flow.
func validateOIDCConfig(cfg OIDCConfig) error {
	if cfg.Issuer == "" {
		return errors.New("oidc: issuer required")
	}
	if cfg.ClientID == "" {
		return errors.New("oidc: client_id required")
	}
	if cfg.RedirectURI == "" {
		return errors.New("oidc: redirect_uri required")
	}
	if _, err := url.Parse(cfg.Issuer); err != nil {
		return fmt.Errorf("oidc: bad issuer: %w", err)
	}
	if _, err := url.Parse(cfg.RedirectURI); err != nil {
		return fmt.Errorf("oidc: bad redirect_uri: %w", err)
	}
	return nil
}

// discoverOIDC fetches /.well-known/openid-configuration and returns
// the endpoints we need.
func discoverOIDC(ctx context.Context, hc *http.Client, issuer string) (providerMetadata, error) {
	u := strings.TrimRight(issuer, "/") + "/.well-known/openid-configuration"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return providerMetadata{}, fmt.Errorf("oidc discover: build req: %w", err)
	}
	resp, err := hc.Do(req)
	if err != nil {
		return providerMetadata{}, fmt.Errorf("oidc discover: %w", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode/100 != 2 {
		return providerMetadata{}, fmt.Errorf("oidc discover %s: status %d", u, resp.StatusCode)
	}
	var meta providerMetadata
	if err := json.Unmarshal(body, &meta); err != nil {
		return providerMetadata{}, fmt.Errorf("oidc discover %s: decode: %w", u, err)
	}
	if meta.AuthorizationEndpoint == "" || meta.TokenEndpoint == "" {
		return providerMetadata{}, fmt.Errorf("oidc discover %s: missing endpoints", u)
	}
	return meta, nil
}

// buildAuthzURL composes the /authorize URL with the standard params
// per RFC 6749 §4.1.1 + RFC 7636 §4.3.
func buildAuthzURL(endpoint string, cfg OIDCConfig, pkce pkcePair, state, scopes string) (string, error) {
	u, err := url.Parse(endpoint)
	if err != nil {
		return "", fmt.Errorf("oidc: parse authorize endpoint: %w", err)
	}
	q := u.Query()
	q.Set("response_type", "code")
	q.Set("client_id", cfg.ClientID)
	q.Set("redirect_uri", cfg.RedirectURI)
	q.Set("scope", scopes)
	q.Set("state", state)
	q.Set("code_challenge", pkce.Challenge)
	q.Set("code_challenge_method", pkce.Method)
	u.RawQuery = q.Encode()
	return u.String(), nil
}

// ensureOpenID guarantees the "openid" scope is present (required by
// the OIDC spec — without it the issuer treats the request as plain
// OAuth2 and won't return an id_token).
func ensureOpenID(scopes []string) []string {
	for _, s := range scopes {
		if s == "openid" {
			return scopes
		}
	}
	return append([]string{"openid"}, scopes...)
}

// awaitCallback runs a one-shot loopback HTTP listener on the
// redirect_uri host:port and returns the first callback URL it
// receives. Used when the OIDC redirect_uri is a local 127.0.0.1
// address (the common pattern for desktop apps).
//
// Returns the raw URL the WebView was redirected to so the caller can
// hand it back into oidcRound.Finish.
func awaitCallback(ctx context.Context, redirectURI string, timeout time.Duration) (string, error) {
	u, err := url.Parse(redirectURI)
	if err != nil {
		return "", fmt.Errorf("oidc callback: parse redirect: %w", err)
	}
	host := u.Host
	if host == "" {
		return "", errors.New("oidc callback: redirect_uri has no host:port")
	}
	ln, err := net.Listen("tcp", host)
	if err != nil {
		return "", fmt.Errorf("oidc callback: listen %s: %w", host, err)
	}
	defer ln.Close()

	got := make(chan string, 1)
	srv := &http.Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			full := u.Scheme + "://" + r.Host + r.URL.RequestURI()
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(callbackOKHTML))
			select {
			case got <- full:
			default:
			}
		}),
		ReadHeaderTimeout: 5 * time.Second,
	}
	go func() { _ = srv.Serve(ln) }()
	defer func() {
		sctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = srv.Shutdown(sctx)
	}()

	if timeout <= 0 {
		timeout = 5 * time.Minute
	}
	select {
	case <-ctx.Done():
		return "", ctx.Err()
	case <-time.After(timeout):
		return "", errors.New("oidc callback: timeout waiting for redirect")
	case full := <-got:
		return full, nil
	}
}

const callbackOKHTML = `<!doctype html>
<html><head><meta charset="utf-8"><title>Weft sign-in</title>
<style>body{font-family:-apple-system,BlinkMacSystemFont,system-ui,sans-serif;
text-align:center;padding:3em;color:#333}</style></head>
<body><h2>Signed in</h2><p>You can close this window and return to Weft.</p>
</body></html>`
