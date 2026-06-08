// keypair_linux.go — Secret Service Get/Set/Delete for the ed25519
// private key used by the keypair-fallback flow.
//
// We deliberately store the raw 64-byte ed25519 private key (the
// canonical seed||pubkey form ed25519.NewKeyFromSeed produces) rather
// than a PEM / JSON wrapper : the keypair item never leaves the local
// session, the keyring already provides at-rest protection (per-user
// master key), and the simpler blob makes the Set/Get path obvious.
//
// Label pattern is "weft-app-keypair:<issuer>". A different "account"
// (issuer) per cluster keeps multiple clusters using distinct keypairs
// side-by-side. Attributes follow the same { service, account }
// shape as keychain_linux.go so SearchItems is precise.
package main

import (
	"crypto/ed25519"
	"fmt"
)

// defaultKeypairStore returns the real Secret Service-backed store.
func defaultKeypairStore() KeypairStore { return linuxKeypair{} }

type linuxKeypair struct{}

func (linuxKeypair) Get(service, account string) (ed25519.PrivateKey, bool, error) {
	blob, ok, err := secretServiceRead(service, account)
	if err != nil {
		return nil, false, fmt.Errorf("keypair secret service get: %w", err)
	}
	if !ok {
		return nil, false, nil
	}
	if len(blob) != ed25519.PrivateKeySize {
		return nil, false, fmt.Errorf("keypair secret service get: stored blob length = %d, want %d", len(blob), ed25519.PrivateKeySize)
	}
	return ed25519.PrivateKey(blob), true, nil
}

func (linuxKeypair) Set(service, account string, priv ed25519.PrivateKey) error {
	if len(priv) != ed25519.PrivateKeySize {
		return fmt.Errorf("keypair secret service set: private key length = %d, want %d", len(priv), ed25519.PrivateKeySize)
	}
	label := "weft-app-keypair:" + account
	if err := secretServiceWrite(label, service, account, []byte(priv), "application/octet-stream"); err != nil {
		return fmt.Errorf("keypair secret service set: %w", err)
	}
	return nil
}

func (linuxKeypair) Delete(service, account string) error {
	if err := secretServiceDelete(service, account); err != nil {
		return fmt.Errorf("keypair secret service delete: %w", err)
	}
	return nil
}
