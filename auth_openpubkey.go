// auth_openpubkey.go — OpenPubkey cert-exchange flow.
//
// OpenPubkey binds an SSH/ed25519 key to an OIDC id_token : the IDP
// signs a PK token that includes the user's public key in its claims,
// the desktop holds the private key, and the cluster verifies the PK
// token + a signature from the desktop on every call. The result is a
// cluster session that is provably bound to a key the operator
// physically holds, with the IDP only involved at sign-in time.
//
// The upstream dex extension we'd target (`/openpubkey/cert`) is not
// shipped yet on the cluster's dex, so this stub :
//
//   - logs that OpenPubkey is unavailable and the user is being routed
//     back through the standard OIDC flow ;
//   - returns a sentinel error the orchestrator (auth.go) catches to
//     fall through to runOIDC.
//
// Once the issuer ships the endpoint, this file's runOpenPubkey will :
//
//  1. Run the OIDC PKCE flow to acquire an id_token (same code path
//     as runOIDC, but we keep the id_token instead of returning it).
//  2. Generate a fresh ed25519 keypair locally.
//  3. POST {id_token, public_key} to <issuer>/openpubkey/cert.
//  4. Receive a PK token (JWT) ; persist (PK token, private key) in
//     Keychain as a single blob.
//  5. The WebView fetch interceptor signs each request with the
//     private key and attaches the PK token as the Bearer value.
package main

import (
	"context"
	"errors"
	"log"
)

// ErrOpenPubkeyUnsupported is returned by runOpenPubkey when the issuer
// does not expose the cert-exchange endpoint. auth.go's orchestrator
// catches it (currently via the explicit fallthrough on the OpenPubkey
// case) and falls back to runOIDC.
var ErrOpenPubkeyUnsupported = errors.New("openpubkey: issuer does not support cert exchange ; falling back to OIDC")

// runOpenPubkey is the stub. It logs and returns the sentinel ; auth.go
// turns that into a clean fallback path.
func runOpenPubkey(ctx context.Context, cfg AuthConfig, picker Picker) (Token, error) {
	log.Printf("weft-app: openpubkey not yet supported by issuer %s ; falling back to OIDC", cfg.Issuer)
	return Token{}, ErrOpenPubkeyUnsupported
}
