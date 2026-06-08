// ssh_passphrase_linux.go — Secret Service getter/setter for SSH key
// passphrases, with an opportunistic fprintd biometric prompt layered
// on top. Separate Secret Service attribute namespace
// ("weft-ssh-passphrase") from the session-token store
// (keychain_linux.go) so removing one doesn't affect the other.
//
// Linux mirror of the keychain_linux.go pattern : SearchItems +
// CreateItem + Item.GetSecret keyed by attribute pair
// { service: "weft-ssh-passphrase", account: <absolute key path> }.
// The freedesktop Secret Service is itself encrypted with the user's
// session keyring master key ; we layer fprintd on top opportunistically
// — if the box is enrolled, the user gets a fingerprint prompt before
// the passphrase is released.
package main

import (
	"errors"
	"fmt"
	"log"
	"time"

	"github.com/godbus/dbus/v5"
)

// sshPassphraseService is the Secret Service attribute under which
// every passphrase entry lives. The pair (service, account) attribute
// match keys the per-key entry.
const sshPassphraseService = "weft-ssh-passphrase"

// sshPassphraseGet returns the passphrase bytes stored for the given
// key path, or nil if no entry exists (the caller can then prompt the
// user via --store-ssh-passphrase). On a fprintd-enrolled machine the
// user is prompted to confirm the fingerprint ; the function silently
// skips the biometric step when the machine isn't enrolled (the Secret
// Service already gates on the session keyring's master password in
// that case, so we don't add a second prompt with no biometric path).
func sshPassphraseGet(keyPath string) ([]byte, error) {
	// Best-effort biometric gate. Failure to surface fprintd is
	// downgraded to a log line — the Secret Service retains its own
	// protection regardless.
	if err := requestFingerprint("Unlock your SSH key passphrase to connect to the Weft cluster"); err != nil {
		return nil, fmt.Errorf("fprintd : %w", err)
	}
	blob, ok, err := secretServiceRead(sshPassphraseService, keyPath)
	if err != nil {
		return nil, fmt.Errorf("secret service get (service=%s account=%s): %w", sshPassphraseService, keyPath, err)
	}
	if !ok {
		return nil, nil
	}
	return blob, nil
}

// sshPassphraseSet stores or replaces the passphrase for the given key
// path. Secret Service items are bound to the local session keyring
// and encrypted with the keyring's master key, so no further at-rest
// tuning is needed.
func sshPassphraseSet(keyPath string, passphrase []byte) error {
	label := "weft-ssh-passphrase:" + keyPath
	if err := secretServiceWrite(label, sshPassphraseService, keyPath, passphrase, "application/octet-stream"); err != nil {
		return fmt.Errorf("secret service set (service=%s account=%s): %w", sshPassphraseService, keyPath, err)
	}
	return nil
}

// sshPassphraseDelete removes the passphrase entry for the given key
// path (no-op when nothing is cached).
func sshPassphraseDelete(keyPath string) error {
	if err := secretServiceDelete(sshPassphraseService, keyPath); err != nil {
		return fmt.Errorf("secret service delete (service=%s account=%s): %w", sshPassphraseService, keyPath, err)
	}
	return nil
}

// ----- fprintd biometric gate via D-Bus ------------------------------
//
// net.reactivated.Fprint is the standard freedesktop fingerprint
// daemon used by GNOME / KDE for PAM fingerprint auth. We poke its
// system-bus API to surface a verification prompt without depending
// on a PAM stack ; absence of the daemon (no fprintd, no enrolled
// reader) is treated as "biometry unavailable, skip silently" —
// mirrors macOS's "best-effort Touch ID, never block the release"
// posture.

const (
	fprintBusName       = "net.reactivated.Fprint"
	fprintManagerPath   = "/net/reactivated/Fprint/Manager"
	fprintManagerIface  = "net.reactivated.Fprint.Manager"
	fprintDeviceIface   = "net.reactivated.Fprint.Device"
	fprintVerifyTimeout = 15 * time.Second
)

// requestFingerprint surfaces an fprintd VerifyStart prompt with the
// given reason. Returns nil when biometry is unavailable (treated as
// "no extra gate"), nil when the user's fingerprint matches, and a
// non-nil error only when the user's verification explicitly fails.
//
// We use the system bus to reach fprintd (the daemon lives there) and
// time-bound the wait so a forgotten verification doesn't hang the
// passphrase release forever.
func requestFingerprint(reason string) error {
	_ = reason // surfaced via the daemon's standard prompt UI ; no API surface to override it
	conn, err := dbus.SystemBus()
	if err != nil {
		// No system bus = no fprintd. Skip silently.
		return nil
	}
	defer conn.Close()

	mgr := conn.Object(fprintBusName, fprintManagerPath)
	var devicePath dbus.ObjectPath
	if err := mgr.Call(fprintManagerIface+".GetDefaultDevice", 0).Store(&devicePath); err != nil {
		// fprintd not installed or no enrolled device. Skip silently.
		log.Printf("weft-app: fprintd not available, skipping biometric prompt (%v)", err)
		return nil
	}
	if devicePath == "" || devicePath == "/" {
		return nil
	}

	dev := conn.Object(fprintBusName, devicePath)
	// Claim "" = current user. Pre-existing claim by the same user is
	// not an error in practice but we treat any failure as "skip" so a
	// busy reader doesn't block the credential release.
	if err := dev.Call(fprintDeviceIface+".Claim", 0, "").Err; err != nil {
		log.Printf("weft-app: fprintd Claim failed, skipping biometric prompt (%v)", err)
		return nil
	}
	defer dev.Call(fprintDeviceIface+".Release", 0)

	// Subscribe to VerifyStatus before VerifyStart so we don't miss
	// the signal in a fast-finger case.
	matchRule := fmt.Sprintf("type='signal',interface='%s',member='VerifyStatus',path='%s'", fprintDeviceIface, devicePath)
	if err := conn.BusObject().Call("org.freedesktop.DBus.AddMatch", 0, matchRule).Err; err != nil {
		log.Printf("weft-app: fprintd AddMatch failed, skipping biometric prompt (%v)", err)
		return nil
	}
	defer conn.BusObject().Call("org.freedesktop.DBus.RemoveMatch", 0, matchRule)

	ch := make(chan *dbus.Signal, 4)
	conn.Signal(ch)
	defer conn.RemoveSignal(ch)

	// "any" finger ; fprintd selects from the enrolled set.
	if err := dev.Call(fprintDeviceIface+".VerifyStart", 0, "any").Err; err != nil {
		log.Printf("weft-app: fprintd VerifyStart failed, skipping biometric prompt (%v)", err)
		return nil
	}
	defer dev.Call(fprintDeviceIface+".VerifyStop", 0)

	deadline := time.After(fprintVerifyTimeout)
	for {
		select {
		case <-deadline:
			return errors.New("fingerprint verification timeout")
		case sig, ok := <-ch:
			if !ok {
				return errors.New("fingerprint signal channel closed")
			}
			if sig.Path != devicePath || sig.Name != fprintDeviceIface+".VerifyStatus" {
				continue
			}
			if len(sig.Body) < 2 {
				continue
			}
			result, _ := sig.Body[0].(string)
			done, _ := sig.Body[1].(bool)
			switch result {
			case "verify-match":
				return nil
			case "verify-no-match", "verify-disconnected", "verify-unknown-error":
				if done {
					return fmt.Errorf("fingerprint verification failed: %s", result)
				}
			case "verify-retry-scan", "verify-swipe-too-short", "verify-finger-not-centered", "verify-remove-and-retry":
				// transient ; let the user try again until deadline
			default:
				if done {
					return fmt.Errorf("fingerprint verification ended: %s", result)
				}
			}
		}
	}
}
