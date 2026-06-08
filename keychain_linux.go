// keychain_linux.go — freedesktop Secret Service Get/Set/Delete for
// the session-token blob via D-Bus. No cgo, no libsecret-1-dev — just
// the org.freedesktop.secrets D-Bus protocol that every freedesktop-
// compliant keyring (GNOME Keyring, KWallet, KeePassXC's secret-service
// plugin) implements.
//
// We persist a single JSON blob (the marshalled Token) under one Item
// per (service, account) pair. service defaults to "weft-app", account
// is the issuer URL so an operator can keep multiple clusters logged
// in side by side. Lookup uses SearchItems with attributes
// { "service": <service>, "account": <account> } so the match is
// precise even when other apps share the default collection.
package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/godbus/dbus/v5"
)

// Secret Service well-known names and object paths.
const (
	ssBusName         = "org.freedesktop.secrets"
	ssServicePath     = "/org/freedesktop/secrets"
	ssCollectionAlias = "/org/freedesktop/secrets/aliases/default"
	ssServiceIface    = "org.freedesktop.Secret.Service"
	ssCollectionIface = "org.freedesktop.Secret.Collection"
	ssItemIface       = "org.freedesktop.Secret.Item"
	ssPromptIface     = "org.freedesktop.Secret.Prompt"
	// Plain transfer algorithm : no encryption between client and
	// daemon. Both live in the user's session, so the threat model is
	// the same as the on-disk keyring DB ; plain keeps the implementation
	// short and matches what most libsecret-backed tools default to.
	ssAlgorithmPlain = "plain"
)

// secret is the (object_path, parameters, value, content_type) struct
// the Secret Service uses for both Item.GetSecret returns and
// CreateItem secret arguments.
type secret struct {
	Session     dbus.ObjectPath
	Parameters  []byte
	Value       []byte
	ContentType string
}

// defaultKeychain returns the real Secret Service-backed store. The
// name "Keychain" is kept across all desktop ports so the
// orchestration code in auth.go stays identical to macOS / Windows.
func defaultKeychain() KeychainStore { return secretServiceKC{} }

type secretServiceKC struct{}

func (secretServiceKC) Get(service, account string) (Token, bool, error) {
	blob, ok, err := secretServiceRead(service, account)
	if err != nil {
		return Token{}, false, err
	}
	if !ok {
		return Token{}, false, nil
	}
	var tok Token
	if err := json.Unmarshal(blob, &tok); err != nil {
		return Token{}, false, fmt.Errorf("secret service get: parse blob: %w", err)
	}
	return tok, true, nil
}

func (secretServiceKC) Set(service, account string, tok Token) error {
	blob, err := json.Marshal(tok)
	if err != nil {
		return fmt.Errorf("secret service set: marshal: %w", err)
	}
	label := "weft-app:" + account
	return secretServiceWrite(label, service, account, blob, "application/json")
}

func (secretServiceKC) Delete(service, account string) error {
	return secretServiceDelete("weft-app", service, account)
}

// dbusConn is overridable by tests ; production hits the user session
// bus directly. Returned connection must be Close()d by the caller.
var dbusConn = func() (*dbus.Conn, error) { return dbus.SessionBus() }

// secretServiceSession opens a transport-plain Secret Service session
// against the running daemon. Returns the session path and a cleanup
// that closes it ; both must be honoured even when the actual
// operation fails so the daemon doesn't leak session objects.
func secretServiceSession(conn *dbus.Conn) (dbus.ObjectPath, func(), error) {
	svc := conn.Object(ssBusName, ssServicePath)
	var output dbus.Variant
	var session dbus.ObjectPath
	if err := svc.Call(ssServiceIface+".OpenSession", 0, ssAlgorithmPlain, dbus.MakeVariant("")).Store(&output, &session); err != nil {
		return "", nil, fmt.Errorf("OpenSession: %w", err)
	}
	cleanup := func() {
		conn.Object(ssBusName, session).Call("org.freedesktop.Secret.Session.Close", 0)
	}
	return session, cleanup, nil
}

// secretServiceUnlockDefault asks the daemon to unlock the default
// collection. When the user has set a master password and the keyring
// is still locked, this returns a Prompt object the agent surfaces ;
// we wait for the agent's reply on the Completed signal. When the
// collection is already unlocked the prompt path is "/" and we return
// immediately.
func secretServiceUnlockDefault(conn *dbus.Conn) error {
	svc := conn.Object(ssBusName, ssServicePath)
	var unlocked []dbus.ObjectPath
	var prompt dbus.ObjectPath
	if err := svc.Call(ssServiceIface+".Unlock", 0, []dbus.ObjectPath{ssCollectionAlias}).Store(&unlocked, &prompt); err != nil {
		return fmt.Errorf("Unlock: %w", err)
	}
	if prompt == "/" {
		return nil
	}
	return promptAndWait(conn, prompt)
}

// promptAndWait drives a Secret Service Prompt object to completion.
// Subscribes to the Completed signal first, then calls Prompt() ; the
// agent shows its UI ; the signal fires when the user accepts or
// dismisses. Returns an error on dismissal so the caller surfaces it.
func promptAndWait(conn *dbus.Conn, prompt dbus.ObjectPath) error {
	matchRule := fmt.Sprintf("type='signal',interface='%s',member='Completed',path='%s'", ssPromptIface, prompt)
	if err := conn.BusObject().Call("org.freedesktop.DBus.AddMatch", 0, matchRule).Err; err != nil {
		return fmt.Errorf("AddMatch: %w", err)
	}
	defer conn.BusObject().Call("org.freedesktop.DBus.RemoveMatch", 0, matchRule)

	ch := make(chan *dbus.Signal, 1)
	conn.Signal(ch)
	defer conn.RemoveSignal(ch)

	if err := conn.Object(ssBusName, prompt).Call(ssPromptIface+".Prompt", 0, "").Err; err != nil {
		return fmt.Errorf("Prompt: %w", err)
	}

	for sig := range ch {
		if sig.Path != prompt || sig.Name != ssPromptIface+".Completed" {
			continue
		}
		if len(sig.Body) < 1 {
			return errors.New("prompt completed without dismissed flag")
		}
		if dismissed, _ := sig.Body[0].(bool); dismissed {
			return errors.New("prompt dismissed by user")
		}
		return nil
	}
	return errors.New("prompt signal channel closed")
}

// secretServiceRead resolves an item by (service, account) attributes
// in the default collection and returns its secret bytes.
// (nil, false, nil) means "no entry found" so callers can treat it as
// a cache miss.
func secretServiceRead(service, account string) ([]byte, bool, error) {
	conn, err := dbusConn()
	if err != nil {
		return nil, false, fmt.Errorf("secret service: connect session bus: %w", err)
	}
	defer conn.Close()

	if err := secretServiceUnlockDefault(conn); err != nil {
		return nil, false, fmt.Errorf("secret service: unlock default collection: %w", err)
	}

	session, closeSess, err := secretServiceSession(conn)
	if err != nil {
		return nil, false, fmt.Errorf("secret service: %w", err)
	}
	defer closeSess()

	attrs := map[string]string{"service": service, "account": account}
	coll := conn.Object(ssBusName, ssCollectionAlias)
	var items []dbus.ObjectPath
	if err := coll.Call(ssCollectionIface+".SearchItems", 0, attrs).Store(&items); err != nil {
		return nil, false, fmt.Errorf("secret service: SearchItems: %w", err)
	}
	if len(items) == 0 {
		return nil, false, nil
	}

	itemPath := items[0]
	var sec secret
	if err := conn.Object(ssBusName, itemPath).Call(ssItemIface+".GetSecret", 0, session).Store(&sec); err != nil {
		return nil, false, fmt.Errorf("secret service: GetSecret: %w", err)
	}
	// Make a copy so the caller doesn't hold a reference into the
	// transient struct.
	out := make([]byte, len(sec.Value))
	copy(out, sec.Value)
	return out, true, nil
}

// secretServiceWrite creates (or replaces) an item under the default
// collection with the given label, attributes, and secret value.
// replace=true is the CreateItem convention every secret-service
// implementation honours.
func secretServiceWrite(label, service, account string, blob []byte, contentType string) error {
	conn, err := dbusConn()
	if err != nil {
		return fmt.Errorf("secret service: connect session bus: %w", err)
	}
	defer conn.Close()

	if err := secretServiceUnlockDefault(conn); err != nil {
		return fmt.Errorf("secret service: unlock default collection: %w", err)
	}

	session, closeSess, err := secretServiceSession(conn)
	if err != nil {
		return fmt.Errorf("secret service: %w", err)
	}
	defer closeSess()

	props := map[string]dbus.Variant{
		ssItemIface + ".Label": dbus.MakeVariant(label),
		ssItemIface + ".Attributes": dbus.MakeVariant(map[string]string{
			"service": service,
			"account": account,
		}),
	}
	sec := secret{
		Session:     session,
		Parameters:  []byte{},
		Value:       blob,
		ContentType: contentType,
	}
	coll := conn.Object(ssBusName, ssCollectionAlias)
	var itemPath, promptPath dbus.ObjectPath
	if err := coll.Call(ssCollectionIface+".CreateItem", 0, props, sec, true).Store(&itemPath, &promptPath); err != nil {
		return fmt.Errorf("secret service: CreateItem: %w", err)
	}
	if promptPath != "/" {
		if err := promptAndWait(conn, promptPath); err != nil {
			return fmt.Errorf("secret service: create item prompt: %w", err)
		}
	}
	return nil
}

// secretServiceDelete removes the matching item from the default
// collection. Missing entries are not an error — the caller's
// expectation is "make sure it's gone".
func secretServiceDelete(service, account string) error {
	conn, err := dbusConn()
	if err != nil {
		return fmt.Errorf("secret service: connect session bus: %w", err)
	}
	defer conn.Close()

	if err := secretServiceUnlockDefault(conn); err != nil {
		return fmt.Errorf("secret service: unlock default collection: %w", err)
	}

	attrs := map[string]string{"service": service, "account": account}
	coll := conn.Object(ssBusName, ssCollectionAlias)
	var items []dbus.ObjectPath
	if err := coll.Call(ssCollectionIface+".SearchItems", 0, attrs).Store(&items); err != nil {
		return fmt.Errorf("secret service: SearchItems: %w", err)
	}
	for _, itemPath := range items {
		var promptPath dbus.ObjectPath
		if err := conn.Object(ssBusName, itemPath).Call(ssItemIface+".Delete", 0).Store(&promptPath); err != nil {
			// Some daemons race-delete the item between SearchItems
			// and Delete ; treat NoSuchObject as success.
			if strings.Contains(err.Error(), "NoSuchObject") {
				continue
			}
			return fmt.Errorf("secret service: Delete: %w", err)
		}
		if promptPath != "/" {
			if err := promptAndWait(conn, promptPath); err != nil {
				return fmt.Errorf("secret service: delete prompt: %w", err)
			}
		}
	}
	return nil
}
