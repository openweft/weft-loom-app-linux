# weft-loom-app-linux

Linux tray client for the [Weft](https://github.com/openweft) dashboard.

A `StatusNotifierItem` in the system tray; **Open Dashboard** shows
[`weft-webui`](https://github.com/openweft/weft-webui) in a WebKit2GTK
window. The connection logic — datacenter discovery, secure transport,
and failover — lives in
[`weft-app-core`](https://github.com/openweft/weft-app-core); this repo
is the GTK tray + WebView glue. It is the same Go shell as
[`weft-app-osx`](https://github.com/openweft/weft-app-osx) and
[`weft-app-windows`](https://github.com/openweft/weft-app-windows), with
`webview_go` resolving to WebKit2GTK here, the macOS Keychain swapped
for the freedesktop Secret Service, and Touch ID swapped for fprintd.

## How it works

Three modes of one binary (one main loop each): the **tray** owns the
failover supervisor + loopback gateway + control server; **Open
Dashboard** spawns the binary in `--dashboard` mode, which loads the
gateway's single stable loopback origin in a WebKit2GTK window and
never re-points it — so a datacenter failover preserves cookies,
session and SPA state, and only the dashboard's "connection switched"
banner blips. The **`--sign-in`** mode opens the auth WebKit2GTK
window when the operator clicks "Sign in" in the tray menu. See the
[`weft-app-core` README](https://github.com/openweft/weft-app-core) for
the full picture.

```
weft-loom-app-linux (tray)                         weft-loom-app-linux --dashboard
───────────────────                         ────────────────────────
shell.Shell                                 WebKit2GTK
  ├─ failover.Supervisor  (probes each DC)    loads gateway origin
  ├─ failover.Gateway     (loopback origin) ◀── stable http://127.0.0.1:PORT
  └─ control.Server       (/active) ──poll──▶ control.Client
        ▲                                       └─ on DC change:
        └ OnSwitch publishes active DC             __weftFailoverNotice → banner
```

## No public web service

Each DC's `weft-webui` is reached over an SSH local-forward (default) or
the WireGuard mesh — the platform exposes no worldwide web listener.
The transport key gates the network, dex OIDC gates the session. See
`config.example.json`.

For the WireGuard transport (pure-Go userspace `wireguard-go`, no `tun`
privilege), pass a mesh config:

```sh
weft-loom-app-linux --config app.json --wg-config wireguard.json
```

See `wireguard.example.json` for the schema (`wg genkey`-style base64
keys).

## Tray menu

- **Active DC label** (top of the menu, disabled) — the operator-facing
  "Cluster · DC" name of the datacenter the dashboard is currently
  reading from. The tray tooltip carries the same string so it's
  visible without opening the menu.
- **Open Dashboard** — spawns the dashboard WebKit2GTK window. Disabled
  until a non-expired session token is cached when `auth` is configured
  in `app.json` (so clicking it can never land on the dex sign-in page
  instead of the SPA).
- **Datacenters** — submenu showing each cluster header + indented per-
  DC rows, glyphed `●` for healthy / `○` for down, with ` — active`
  on the currently-selected DC.
- **Switch cluster** — submenu listing every cluster declared in
  `app.json`. Only present when more than one cluster is configured.
  Clicking a cluster quarantines every endpoint outside it so failover
  stays scoped ; the SPA's Topbar chip + the tray tooltip update via
  the usual `OnSwitch` path.
- **Sign in** / **Sign out** — only present when an `auth` block is
  declared. "Sign in" spawns the `--sign-in` subprocess (WebKit2GTK
  with `login.html`) ; on success the new token is in the Secret
  Service and the tray reads it back. "Sign out" deletes the cached
  token.
- **Quit** — terminates the supervisor, gateway, and control server.

## Build

Debian/Ubuntu build deps:

```sh
sudo apt install libgtk-3-dev libwebkit2gtk-4.1-dev pkg-config
cp config.example.json ~/.config/weft/app.json   # then edit for your cluster
task deps && task build
```

WebKit2GTK 4.1 is the current API ; the older `libwebkit2gtk-4.0-dev`
also works on distros that haven't moved to 4.1 yet (the
`webview_go` cgo glue picks whichever is available). The Secret
Service stack ships with every modern desktop keyring (GNOME
Keyring, KWallet, KeePassXC's secret-service plugin) ; `fprintd`
is optional and only used to surface a fingerprint prompt before
releasing the SSH passphrase.

Packaging as a Flatpak: `task flatpak`. AppImage / `.deb` workflows
are tracked separately ; not yet in this repo.

## Encrypted SSH key + fingerprint passphrase

The SSH transport accepts a passphrase-protected key — the recommended
posture — without prompting on every launch. The flow :

```
   ┌─────────────────┐    ┌────────────────────────┐  ┌──────────────────┐
   │ ~/.ssh/id_ed25519│   │ freedesktop Secret      │  │ weft-loom-app-linux     │
   │ (PEM, encrypted) │   │  Service (GNOME         │  │                  │
   │                  │   │  Keyring / KWallet)     │  │ SSHForward       │
   │                  │   │ service=                │  │ (bastion hosts)  │
   │                  │   │  weft-ssh-passphrase    │  │                  │
   │                  │   │ account=<key path>      │  │                  │
   └────────┬─────────┘   └─────────┬──────────────┘  └────────┬─────────┘
            │                       │                          │
            │ read PEM              │ release passphrase       │ ssh dial
            └──────┬────────────────┘  (fprintd gate)          │
                   │                       │                   │
                   ▼                       │                   │
   ssh.ParsePrivateKeyWithPassphrase(pem, passphrase) ─────────┘
```

**One-shot setup**

```bash
# 1. Make sure the key is actually passphrase-protected. If you generated
#    it without one and want to add one :
ssh-keygen -p -f ~/.ssh/id_ed25519
# Old passphrase: (empty)
# New passphrase: ●●●●●●●●

# 2. Stage the passphrase in the Secret Service. Prompts on /dev/tty
#    with echo off, so it never lands in shell history or env vars.
weft-loom-app-linux --store-ssh-passphrase ~/.ssh/id_ed25519
# Enter passphrase for /home/<you>/.ssh/id_ed25519 (empty if none):
# ●●●●●●●●
# weft-app: passphrase cached in Secret Service
#           (service=weft-ssh-passphrase account=/home/<you>/.ssh/id_ed25519)
```

**Subsequent launches** — the tray's shell calls `sshPassphraseGet`
when `ssh.ParsePrivateKey` returns `*ssh.PassphraseMissingError`; the
Secret Service release is gated by the session keyring's master key,
with an opportunistic `fprintd` fingerprint prompt on top.

**fprintd** — when the box is enrolled (a fingerprint reader is wired
up and the user has registered at least one finger under
**Settings → Users → Add Fingerprint**, or via `fprintd-enroll`),
the SSH passphrase release surfaces the standard fprintd verify
prompt. When the box is NOT enrolled (no biometric hardware, fprintd
not installed), the biometric step is silently skipped — the Secret
Service release falls back to the session keyring's master key gate,
which is what GNOME Keyring / KWallet do for every secret anyway. So
the app keeps working on boxes without a fingerprint reader, and the
biometric protection layers on transparently when the hardware is
present.

**Rotation** — re-running `--store-ssh-passphrase` overwrites the
entry. To wipe :

```bash
secret-tool clear service weft-ssh-passphrase account ~/.ssh/id_ed25519
```

The Secret Service entry is per-key-file-path, so multiple keys
(e.g. one per production cluster) coexist without colliding.

## Sign-in & authentication

When the `auth` block is present in `app.json`, the tray's "Sign in"
menu item opens the WebKit2GTK login window (`login.html`) with two
buttons :

- **Sign in with OIDC** — runs the Authorization Code + PKCE flow
  against the configured `issuer` (dex by default). The same
  WebKit2GTK navigates to the IdP login page ; the loopback HTTP
  listener captures the redirect. The resulting id_token is cached in
  the Secret Service.
- **Sign in with OpenPubkey** — bound to dex's `/openpubkey/cert`
  endpoint. Surfaced as a stub until the cluster's dex ships the
  extension ; clicking it falls back to OIDC.

A third **Sign in with local key (dev)** button appears when
`keypair_fallback = true` is set in `app.json` and `gateway` points to
the cluster origin. The app loads (or generates + persists) an
ed25519 private key in the Secret Service (label prefix
`weft-app-keypair`), signs a 60-second assertion bound to
`gateway/api/auth/keypair`, and POSTs it ; the server returns a
session id_token if the matching public key is in its
`--keypair-allowlist` file. Register your pubkey by running
`weft-loom-app-linux --print-pubkey` and pasting the output into the
server's allowlist.

## Tested logic

The non-UI logic is covered by tests in this repo
(`auth_test.go`, `auth_keypair_test.go`, `auth_oidc_test.go`,
`wgmesh_test.go`) and in `weft-app-core` (`failover`, `shell`,
`control`, `discovery`). This repo's `main` package is the thin
D-Bus + WebKit2GTK shell.
