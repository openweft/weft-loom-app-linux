package main

import (
	"encoding/base64"
	"strings"
	"testing"
)

func TestB64ToHex(t *testing.T) {
	key := base64.StdEncoding.EncodeToString(make([]byte, 32))
	h, err := b64ToHex(key)
	if err != nil {
		t.Fatal(err)
	}
	if len(h) != 64 || strings.Trim(h, "0") != "" {
		t.Fatalf("hex = %q (want 64 zero hex chars)", h)
	}
	if _, err := b64ToHex("not!base64"); err == nil {
		t.Fatal("expected error on invalid base64")
	}
}

func TestParseAddrs(t *testing.T) {
	addrs, err := parseAddrs([]string{"10.80.9.2/32", " 10.80.9.3 ", ""})
	if err != nil {
		t.Fatal(err)
	}
	if len(addrs) != 2 || addrs[0].String() != "10.80.9.2" || addrs[1].String() != "10.80.9.3" {
		t.Fatalf("addrs = %v", addrs)
	}
	if _, err := parseAddrs([]string{"not-an-ip"}); err == nil {
		t.Fatal("expected error on bad address")
	}
}

func TestUAPIConfigRendersWireGuardKeys(t *testing.T) {
	key := base64.StdEncoding.EncodeToString(make([]byte, 32))
	uapi, err := uapiConfig(WGConfig{
		PrivateKey: key,
		Peers: []WGPeer{{
			PublicKey:           key,
			Endpoint:            "gw-a.example.com:51820",
			AllowedIPs:          []string{"10.80.0.0/16"},
			PersistentKeepalive: 25,
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"private_key=" + strings.Repeat("0", 64),
		"public_key=" + strings.Repeat("0", 64),
		"endpoint=gw-a.example.com:51820",
		"persistent_keepalive_interval=25",
		"allowed_ip=10.80.0.0/16",
	} {
		if !strings.Contains(uapi, want) {
			t.Fatalf("uapi missing %q\n---\n%s", want, uapi)
		}
	}
	if _, err := uapiConfig(WGConfig{PrivateKey: "bad!"}); err == nil {
		t.Fatal("expected error on invalid private key")
	}
}
