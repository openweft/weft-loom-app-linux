// auth_login.go : the operator-facing sign-in window. A single
// WebKit2GTK window shows the bundled login.html. JS calls Go
// directly via webview_go's Bind (which on Linux is wired through
// WebKit2GTK's user-script-message API), the Go side runs the actual
// auth flow (Keypair / OIDC / OpenPubkey) and destroys the window on
// success. OIDC reuses the existing PKCE state machine ; instead of
// opening a SECOND WebView for the issuer login, we let the SAME
// WebView navigate there — the loopback HTTP listener picks the code
// off the redirect as before.
//
// One window, one window-management problem. The login.html ships as
// a //go:embed asset so there's no on-disk path or temp file.
package main

import (
	"context"
	_ "embed"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"strings"
	"sync"
	"time"

	webview "github.com/webview/webview_go"

	corauth "github.com/openweft/weft-app-core/auth"
)

//go:embed login.html
var loginHTML []byte

// runLoginWebView opens the WebKit2GTK picker, blocks on the WebView's
// run loop, and returns the Token cached in the Secret Service by
// whichever auth flow the operator picked. The window is destroyed
// before this function returns ; the caller may proceed straight to
// runTray.
//
// store is used only for the keypair flow's Keychain write ; OIDC's
// own writer (auth.go's Authenticate path) is delegated to here via a
// closure passed in oidcDeps. nil store falls back to defaultKeychain.
func runLoginWebView(ctx context.Context, cfg AuthConfig, store KeychainStore) (Token, error) {
	if store == nil {
		store = defaultKeychain()
	}

	promoteDashboardActivation() // bring the subprocess to the foreground

	w := webview.New(false)
	defer w.Destroy()
	w.SetTitle("Sign in to Weft")
	w.SetSize(420, 480, webview.HintFixed)

	// JS-visible knobs : keypair button gate + branding strings.
	conf := map[string]any{
		"keypair_fallback": cfg.KeypairFallback,
		"issuer":           cfg.Issuer,
		"version":          version,
	}
	confBytes, _ := json.Marshal(conf)
	w.Init("window.weftConfig = " + string(confBytes) + ";")

	// loginResult ferries the Token from the auth-method goroutine to
	// the main thread, which exits w.Run() by calling w.Terminate()
	// once it has the token (or an error to surface back to the user).
	var (
		resultMu  sync.Mutex
		result    Token
		resultErr error
		resultSet bool
	)
	setResult := func(t Token, err error) {
		resultMu.Lock()
		defer resultMu.Unlock()
		if resultSet {
			return
		}
		result, resultErr, resultSet = t, err, true
		// Tear down the window from the main thread. webview.Terminate
		// is safe to call from any goroutine.
		w.Terminate()
	}

	// ---- Keypair flow : signed assertion → /api/auth/keypair → token
	w.Bind("weftSignInKeypair", func() error {
		tok, err := runKeypair(ctx, cfg)
		if err != nil {
			return err
		}
		if err := store.Set(cfg.KeychainService, cfg.KeychainAccount, tok); err != nil {
			return fmt.Errorf("keychain write: %w", err)
		}
		setResult(tok, nil)
		return nil
	})

	// ---- OIDC PKCE : returns authorize URL ; same WebView navigates
	// there ; the loopback listener captures the code asynchronously.
	w.Bind("weftStartOIDC", func() (string, error) {
		round, err := startOIDC(ctx, cfg.OIDCConfig())
		if err != nil {
			return "", err
		}
		// Start the loopback listener in a goroutine — it returns once
		// the IdP redirects with the code (or an error). The listener
		// writes the captured callback URL into the round's Finish().
		go func() {
			cb, err := awaitCallback(ctx, cfg.RedirectURI, 5*time.Minute)
			if err != nil {
				setResult(Token{}, fmt.Errorf("oidc callback: %w", err))
				return
			}
			tok, err := round.Finish(ctx, cb)
			if err != nil {
				setResult(Token{}, fmt.Errorf("oidc exchange: %w", err))
				return
			}
			if err := store.Set(cfg.KeychainService, cfg.KeychainAccount, tok); err != nil {
				setResult(Token{}, fmt.Errorf("keychain write: %w", err))
				return
			}
			setResult(tok, nil)
		}()
		return round.AuthorizeURL(), nil
	})

	// ---- OpenPubkey : upstream stub for now. Surface the stub error
	// to the WebView so the user gets a real message rather than a
	// silent close.
	w.Bind("weftSignInOpenPubkey", func() error {
		if errors.Is(ErrOpenPubkeyUnsupported, nil) {
			return errors.New("openpubkey: not implemented in this build")
		}
		return ErrOpenPubkeyUnsupported
	})

	// data: URL avoids needing a local file path or HTTP server for
	// the page itself. The IdP redirect goes to a different origin
	// (the loopback listener) so the same-origin restriction doesn't
	// bite.
	w.Navigate("data:text/html;base64," + base64.StdEncoding.EncodeToString(loginHTML))

	// Listen for context cancel → close the window without a token.
	// Run on a goroutine so w.Run() owns the main thread.
	go func() {
		<-ctx.Done()
		setResult(Token{}, ctx.Err())
	}()

	w.Run() // blocks until setResult → w.Terminate()

	resultMu.Lock()
	defer resultMu.Unlock()
	return result, resultErr
}

// helper : AuthConfig.OIDCConfig peels out the OIDC subset for
// startOIDC. Kept inline because callers don't need the full
// AuthConfig surface, only the OIDC fields.
func (c AuthConfig) OIDCConfig() OIDCConfig {
	return OIDCConfig{
		Issuer:      c.Issuer,
		ClientID:    c.ClientID,
		Scopes:      c.Scopes,
		RedirectURI: c.RedirectURI,
	}
}

// stripCRLF is here so the package's lint stays clean if a future
// edit reaches for a one-line trim ; auth_login.go intentionally
// does NOT touch the loopback / redirect URI parsing.
func stripCRLF(s string) string { return strings.TrimRight(s, "\r\n") }

// silence the linter — corauth + log + http are imported so the
// future hook points (e.g. logging the chosen method) don't need
// import churn.
var _ = corauth.EncodePubKey
var _ = log.Printf
var _ = http.DefaultClient
