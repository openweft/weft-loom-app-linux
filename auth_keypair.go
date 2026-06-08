// auth_keypair.go — ed25519 keypair fallback flow.
//
// runKeypair is the orchestration : load (or generate + persist) the
// ed25519 private key from the platform credential store (freedesktop
// Secret Service here ; macOS Keychain / Windows Credential Manager
// on the sibling desktop builds), sign a fresh assertion for the
// configured gateway, POST it to /api/auth/keypair, and return the
// resulting session token. The D-Bus calls live in keypair_linux.go —
// this file is pure Go so the logic is shared across desktop ports.
//
// This auth path is opt-in twice : the client config must set
// auth.keypair_fallback = true AND the server must be started with
// --keypair-allowlist <path>. Either missing = no surface.
package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"
	"time"

	corauth "github.com/openweft/weft-app-core/auth"
)

// KeypairKeychainService is the kSecAttrService string the ed25519
// private key is stored under. Distinct from the session-token store
// ("weft-app") so an operator can rotate sessions without losing the
// keypair, and so SecItemCopyMatching never returns the wrong blob.
const KeypairKeychainService = "weft-app-keypair"

// keypairAccountFor returns the kSecAttrAccount the keypair Keychain
// item is stored under. We tie it to the AuthConfig.Issuer so the
// operator can keep one keypair per cluster ; an empty Issuer collapses
// to a fixed bucket so the dev-only `--print-pubkey` short-circuit
// still finds (or generates) the key without a full app.json.
func keypairAccountFor(cfg AuthConfig) string {
	if cfg.Issuer != "" {
		return cfg.Issuer
	}
	return "default"
}

// loadOrCreateKeypair fetches the ed25519 private key from Keychain,
// generating + persisting a new one on miss. The matching public key
// is the second half of the private blob — ed25519.PrivateKey
// canonically holds seed || pubkey, so no separate storage is needed.
// Returns the canonical 64-byte private key + the derived public key.
func loadOrCreateKeypair(store KeypairStore, account string) (ed25519.PrivateKey, ed25519.PublicKey, bool, error) {
	priv, ok, err := store.Get(KeypairKeychainService, account)
	if err != nil {
		return nil, nil, false, fmt.Errorf("keypair: keychain get: %w", err)
	}
	if ok {
		pub, ok := priv.Public().(ed25519.PublicKey)
		if !ok {
			return nil, nil, false, errors.New("keypair: stored private key has no usable public half")
		}
		return priv, pub, false, nil
	}
	priv, pub, err := corauth.GenerateKeypair()
	if err != nil {
		return nil, nil, false, err
	}
	if err := store.Set(KeypairKeychainService, account, priv); err != nil {
		return nil, nil, false, fmt.Errorf("keypair: keychain write: %w", err)
	}
	return priv, pub, true, nil
}

// runKeypair runs the dev keypair flow end-to-end. cfg.Gateway must be
// non-empty (the endpoint we POST to). cfg.KeypairFallback is assumed
// true ; auth.go only dispatches here when the user picked the 3rd
// button.
func runKeypair(ctx context.Context, cfg AuthConfig) (Token, error) {
	if cfg.Gateway == "" {
		return Token{}, errors.New("keypair: auth.gateway is required when keypair_fallback=true")
	}
	priv, pub, fresh, err := loadOrCreateKeypair(defaultKeypairStore(), keypairAccountFor(cfg))
	if err != nil {
		return Token{}, err
	}
	if fresh {
		// First-run UX : the operator needs to paste this pubkey into
		// the server's --keypair-allowlist file. Print to stderr so
		// `weft-app-osx 2>>weft-app.log` captures it.
		fmt.Fprintf(stderr, "weft-app: generated a new ed25519 keypair for the dev fallback.\n"+
			"          register this pubkey on the server's keypair allowlist :\n"+
			"          %s\n", corauth.EncodePubKey(pub))
	}

	audience := strings.TrimRight(cfg.Gateway, "/") + "/api/auth/keypair"
	jws, err := corauth.SignAssertion(priv, audience)
	if err != nil {
		return Token{}, err
	}
	return postKeypairAssertion(ctx, http.DefaultClient, audience, jws)
}

// keypairResponse is the shape /api/auth/keypair returns on a 200.
type keypairResponse struct {
	IDToken       string `json:"id_token"`
	Kind          string `json:"kind"`
	ExpiresAtUnix int64  `json:"expires_at_unix"`
}

// postKeypairAssertion POSTs the JWS and parses the response. Pulled
// out as a top-level so the http.Client can be swapped in tests.
func postKeypairAssertion(ctx context.Context, client *http.Client, endpoint string, jws corauth.Assertion) (Token, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader([]byte(jws)))
	if err != nil {
		return Token{}, fmt.Errorf("keypair: build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/jose; charset=utf-8")
	req.Header.Set("Accept", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return Token{}, fmt.Errorf("keypair: post: %w", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode == http.StatusNotFound {
		return Token{}, errors.New("keypair: server has --keypair-allowlist disabled (404)")
	}
	if resp.StatusCode != http.StatusOK {
		return Token{}, fmt.Errorf("keypair: server status %d : %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}
	var r keypairResponse
	if err := json.Unmarshal(body, &r); err != nil {
		return Token{}, fmt.Errorf("keypair: parse response: %w", err)
	}
	if r.IDToken == "" {
		return Token{}, errors.New("keypair: server returned no id_token")
	}
	tok := Token{
		Kind:     TokenKindKeypair,
		IDToken:  r.IDToken,
		IssuedAt: time.Now().UTC(),
	}
	if r.ExpiresAtUnix > 0 {
		tok.ExpiresAt = time.Unix(r.ExpiresAtUnix, 0).UTC()
	}
	log.Printf("weft-app: keypair auth ok ; token kind=%s expires=%s", r.Kind, tok.ExpiresAt)
	return tok, nil
}

// KeypairStore is the seam between the orchestration in this file and
// the per-platform raw-private-key store. keypair_linux.go returns
// the Secret Service implementation ; tests inject an in-memory
// double.
type KeypairStore interface {
	Get(service, account string) (ed25519.PrivateKey, bool, error)
	Set(service, account string, priv ed25519.PrivateKey) error
	Delete(service, account string) error
}

// stderr is a package-level seam so tests can capture the
// "register this pubkey" diagnostic without hijacking os.Stderr at the
// process level. Set in main.go's init path is not required ; the zero
// value (io.Discard) is overridden in main() by the real os.Stderr.
var stderr io.Writer = io.Discard
