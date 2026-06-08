//go:build !linux

// keychain_stub.go — non-Linux build glue so `go test ./...` runs on
// the maintainer's macOS / Windows host without conjuring a separate
// build matrix. The real Secret Service / fprintd bindings live in
// keychain_linux.go / keypair_linux.go / ssh_passphrase_linux.go,
// each gated by the `_linux.go` filename suffix.
//
// The stubs below intentionally return "miss / not implemented" so a
// developer who accidentally tries to invoke them on the wrong OS gets
// a clear error instead of silent data loss. Tests that need a working
// store inject memKC / memKeypair in-memory doubles instead (see
// auth_test.go / auth_keypair_test.go).
package main

import (
	"crypto/ed25519"
	"errors"
)

// errStubPlatform is the sentinel both stub stores return on Set / Get.
// We surface it instead of panicking so tests that call into Authenticate
// without an explicit double get a readable failure.
var errStubPlatform = errors.New("secret service: this build is not the Linux binary")

// stubKC implements KeychainStore for non-Linux builds. Get reports
// "no cached token" so the orchestrator falls through to the picker /
// login WebView ; Set / Delete return errStubPlatform.
type stubKC struct{}

func (stubKC) Get(service, account string) (Token, bool, error) { return Token{}, false, nil }
func (stubKC) Set(service, account string, t Token) error       { return errStubPlatform }
func (stubKC) Delete(service, account string) error             { return errStubPlatform }

func defaultKeychain() KeychainStore { return stubKC{} }

// stubKP implements KeypairStore for non-Linux builds.
type stubKP struct{}

func (stubKP) Get(service, account string) (ed25519.PrivateKey, bool, error) {
	return nil, false, nil
}
func (stubKP) Set(service, account string, p ed25519.PrivateKey) error { return errStubPlatform }
func (stubKP) Delete(service, account string) error                    { return errStubPlatform }

func defaultKeypairStore() KeypairStore { return stubKP{} }

// sshPassphraseService is the Secret Service attribute prefix the
// production code uses ; the constant is declared in the stub too so
// main.go's `--store-ssh-passphrase` diagnostic compiles on every
// host without diverging.
const sshPassphraseService = "weft-ssh-passphrase"

func sshPassphraseGet(keyPath string) ([]byte, error) { return nil, nil }
func sshPassphraseSet(keyPath string, pp []byte) error {
	return errStubPlatform
}
func sshPassphraseDelete(keyPath string) error { return errStubPlatform }
