module github.com/openweft/weft-loom-app-linux

go 1.26

require (
	fyne.io/systray v1.11.0
	github.com/godbus/dbus/v5 v5.1.0
	github.com/openweft/weft-app-core v0.0.0-20260607093739-70e9dcfc325b
	github.com/webview/webview_go v0.0.0-20240831120633-6173450d4dd6
	golang.org/x/term v0.43.0
	golang.zx2c4.com/wireguard v0.0.0-20260522210424-ecfc5a8d5446
)

// tun/netstack ships both as a subpackage of the wireguard module (above)
// and as a stale standalone module; exclude the latter so the import
// resolves unambiguously to the bundled package.
exclude golang.zx2c4.com/wireguard/tun/netstack v0.0.0-20220703234212-c31a7b1ab478

require (
	github.com/google/btree v1.1.2 // indirect
	golang.org/x/crypto v0.52.0 // indirect
	golang.org/x/net v0.54.0 // indirect
	golang.org/x/sys v0.45.0 // indirect
	golang.org/x/time v0.7.0 // indirect
	golang.zx2c4.com/wintun v0.0.0-20230126152724-0fa3db229ce2 // indirect
	gvisor.dev/gvisor v0.0.0-20250503011706-39ed1f5ac29c // indirect
)
