package main

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"net/netip"
	"os"
	"strings"

	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun/netstack"

	"github.com/openweft/weft-app-core/transport"
)

// WGConfig is a userspace WireGuard tunnel: the device joins the cluster
// mesh as a peer and the resulting dialer reaches every DC's weft-webui
// on its mesh address — so the platform exposes no public web listener.
// Keys are standard base64 (the format `wg genkey` emits).
type WGConfig struct {
	PrivateKey string   `json:"private_key"`   // base64, this device's key
	Addresses  []string `json:"addresses"`     // mesh IPs assigned to this device, e.g. ["10.80.9.2/32"]
	DNS        []string `json:"dns,omitempty"` // optional in-mesh resolvers
	MTU        int      `json:"mtu,omitempty"` // default 1420
	Peers      []WGPeer `json:"peers"`
}

// WGPeer is one mesh peer (typically a per-DC gateway/router).
type WGPeer struct {
	PublicKey           string   `json:"public_key"`              // base64
	PresharedKey        string   `json:"preshared_key,omitempty"` // base64, optional
	Endpoint            string   `json:"endpoint"`                // host:port reachable from the device
	AllowedIPs          []string `json:"allowed_ips"`             // CIDRs routed to this peer
	PersistentKeepalive int      `json:"persistent_keepalive,omitempty"`
}

// LoadWGConfig reads a WGConfig from a JSON file.
func LoadWGConfig(path string) (WGConfig, error) {
	var c WGConfig
	b, err := os.ReadFile(path)
	if err != nil {
		return c, fmt.Errorf("read wireguard config %s: %w", path, err)
	}
	if err := json.Unmarshal(b, &c); err != nil {
		return c, fmt.Errorf("parse wireguard config %s: %w", path, err)
	}
	return c, nil
}

// MeshDialer brings up the userspace WireGuard tunnel and returns a
// DialContextFunc to hand to shell.Options.MeshDialer, plus a closer that
// tears the tunnel down. Pure Go (wireguard-go netstack) — no tun device,
// no privilege, no cgo.
func MeshDialer(c WGConfig) (transport.DialContextFunc, func() error, error) {
	addrs, err := parseAddrs(c.Addresses)
	if err != nil {
		return nil, nil, fmt.Errorf("addresses: %w", err)
	}
	dnsAddrs, err := parseAddrs(c.DNS)
	if err != nil {
		return nil, nil, fmt.Errorf("dns: %w", err)
	}
	mtu := c.MTU
	if mtu == 0 {
		mtu = 1420
	}

	tun, tnet, err := netstack.CreateNetTUN(addrs, dnsAddrs, mtu)
	if err != nil {
		return nil, nil, fmt.Errorf("create netstack tun: %w", err)
	}

	dev := device.NewDevice(tun, conn.NewDefaultBind(), device.NewLogger(device.LogLevelError, "wg "))
	uapi, err := uapiConfig(c)
	if err != nil {
		dev.Close()
		return nil, nil, err
	}
	if err := dev.IpcSet(uapi); err != nil {
		dev.Close()
		return nil, nil, fmt.Errorf("apply wireguard config: %w", err)
	}
	if err := dev.Up(); err != nil {
		dev.Close()
		return nil, nil, fmt.Errorf("bring wireguard up: %w", err)
	}

	dial := func(ctx context.Context, network, address string) (net.Conn, error) {
		return tnet.DialContext(ctx, network, address)
	}
	return dial, func() error { dev.Close(); return nil }, nil
}

// uapiConfig renders the wireguard-go IPC config string (hex keys).
func uapiConfig(c WGConfig) (string, error) {
	priv, err := b64ToHex(c.PrivateKey)
	if err != nil {
		return "", fmt.Errorf("private_key: %w", err)
	}
	var b strings.Builder
	fmt.Fprintf(&b, "private_key=%s\n", priv)
	for i, p := range c.Peers {
		pub, err := b64ToHex(p.PublicKey)
		if err != nil {
			return "", fmt.Errorf("peer %d public_key: %w", i, err)
		}
		fmt.Fprintf(&b, "public_key=%s\n", pub)
		if p.PresharedKey != "" {
			psk, err := b64ToHex(p.PresharedKey)
			if err != nil {
				return "", fmt.Errorf("peer %d preshared_key: %w", i, err)
			}
			fmt.Fprintf(&b, "preshared_key=%s\n", psk)
		}
		if p.Endpoint != "" {
			fmt.Fprintf(&b, "endpoint=%s\n", p.Endpoint)
		}
		if p.PersistentKeepalive > 0 {
			fmt.Fprintf(&b, "persistent_keepalive_interval=%d\n", p.PersistentKeepalive)
		}
		for _, cidr := range p.AllowedIPs {
			fmt.Fprintf(&b, "allowed_ip=%s\n", cidr)
		}
	}
	return b.String(), nil
}

func b64ToHex(s string) (string, error) {
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(s))
	if err != nil {
		return "", fmt.Errorf("not valid base64: %w", err)
	}
	return hex.EncodeToString(raw), nil
}

func parseAddrs(ss []string) ([]netip.Addr, error) {
	out := make([]netip.Addr, 0, len(ss))
	for _, s := range ss {
		s = strings.TrimSpace(s)
		if s == "" {
			continue
		}
		// Accept either "10.80.9.2" or "10.80.9.2/32".
		if i := strings.IndexByte(s, '/'); i >= 0 {
			s = s[:i]
		}
		a, err := netip.ParseAddr(s)
		if err != nil {
			return nil, fmt.Errorf("parse address %q: %w", s, err)
		}
		out = append(out, a)
	}
	return out, nil
}
