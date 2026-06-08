package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"os/exec"
	"os/signal"
	"syscall"
	"time"

	"fyne.io/systray"

	"github.com/openweft/weft-app-core/control"
	"github.com/openweft/weft-app-core/failover"
	"github.com/openweft/weft-app-core/shell"
)

// runTray is the default mode: own the supervisor + gateway + control
// server, and present the StatusNotifierItem. Blocks on the systray
// run loop. A setup failure (bad config, etc.) shows an error tray
// rather than exiting invisibly — a tray app has no console to print to.
//
// authToken is the Bearer string Authenticate produced (or "" when auth
// is disabled in app.json) ; it gets wired into shell.Options.AuthToken
// (so InitScript stamps the fetch interceptor) and threaded into the
// dashboard subprocess via the WEFT_AUTH_TOKEN env var.
func runTray(configPath, wgConfigPath, authToken string, authCfg AuthConfig) {
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	sh, controlURL, err := setupShell(ctx, configPath, wgConfigPath, authToken)
	if err != nil {
		log.Printf("weft-app: %v", err)
		systray.Run(onSetupError(ctx, err), cancel)
		return
	}
	systray.Run(onReady(ctx, sh, controlURL, authToken, authCfg), cancel)
}

// setupShell builds the WireGuard dialer (if configured), the shell, and
// the control server, and starts them bound to ctx. Returns the shell
// and the control-server origin. authToken (when non-empty) is wired
// into shell.Options so InitScript layers in the WebView Bearer
// interceptor.
func setupShell(ctx context.Context, configPath, wgConfigPath, authToken string) (*shell.Shell, string, error) {
	cfg, err := shell.LoadConfig(configPath)
	if err != nil {
		return nil, "", err
	}

	opts := shell.Options{
		AuthToken: authToken,
		// SSHPassphrase reads from the freedesktop Secret Service
		// (service=weft-ssh-passphrase, account=<absolute key path>).
		// The operator pre-stages an entry via `weft-loom-app-linux
		// --store-ssh-passphrase <path>` ; the lookup is silent on
		// miss (returns nil), letting the underlying parse error
		// surface a clear next-step message.
		SSHPassphrase: func(keyPath string) ([]byte, error) {
			return sshPassphraseGet(keyPath)
		},
	}
	if wgConfigPath != "" {
		wc, err := LoadWGConfig(wgConfigPath)
		if err != nil {
			return nil, "", err
		}
		dial, closeMesh, err := MeshDialer(wc)
		if err != nil {
			return nil, "", fmt.Errorf("wireguard: %w", err)
		}
		go func() { <-ctx.Done(); _ = closeMesh() }()
		opts.MeshDialer = dial
	}

	ctrl := control.NewServer()
	opts.OnSwitch = ctrl.Publish
	sh, err := shell.New(cfg, opts)
	if err != nil {
		return nil, "", err
	}

	go func() {
		if err := sh.Run(ctx); err != nil {
			log.Printf("weft-app: gateway stopped: %v", err)
		}
	}()

	controlURL, err := ctrl.Listen(ctx)
	if err != nil {
		return nil, "", fmt.Errorf("control server: %w", err)
	}
	return sh, controlURL, nil
}

// onSetupError shows a minimal tray surfacing the startup error, so the
// user can read it and quit (instead of the app silently not appearing).
func onSetupError(ctx context.Context, setupErr error) func() {
	return func() {
		systray.SetTemplateIcon(iconTemplateData, iconData)
		systray.SetTitle("Loom")
		systray.SetTooltip("Loom — configuration error")
		systray.AddMenuItem("⚠ "+setupErr.Error(), "Startup error").Disable()
		systray.AddSeparator()
		mQuit := systray.AddMenuItem("Quit", "Quit Weft")
		select {
		case <-ctx.Done():
		case <-mQuit.ClickedCh:
		}
		systray.Quit()
	}
}

// onReady builds the menu and wires its actions. systray calls it once
// the status item is live. authToken is forwarded to the dashboard
// subprocess via WEFT_AUTH_TOKEN so its WebView fetch interceptor can
// stamp the Bearer header ; authCfg is used by the "Sign out" item to
// locate the right Secret Service entry to evict.
//
// Linux StatusNotifierItem doesn't have a macOS-style title slot next
// to the tray icon ; the active "Cluster · DC" name lives in the
// tooltip (refreshStatus updates it) and as a disabled label at the
// top of the menu so the operator can read it without hovering.
func onReady(ctx context.Context, sh *shell.Shell, controlURL, authToken string, authCfg AuthConfig) func() {
	return func() {
		systray.SetTemplateIcon(iconTemplateData, iconData)
		systray.SetTitle("Loom")
		systray.SetTooltip("Loom " + version + " — datacenter unknown")

		// Disabled label at the top of the menu carrying the active
		// DC name. refreshStatus updates its title on every probe.
		mActive := systray.AddMenuItem("Loom "+version, "Active cluster + datacenter")
		mActive.Disable()
		systray.AddSeparator()

		mOpen := systray.AddMenuItem("Open Dashboard", "Open the Weft dashboard")
		// Open Dashboard is disabled until we have a usable token when
		// auth is configured. Without that gate, clicking it would
		// spawn a WebKit2GTK pointed at an origin every request to
		// which would be redirected to the sign-in page by the webui —
		// the dashboard would render OIDC chrome instead of the SPA.
		// When auth isn't configured (omitted from app.json) the item
		// stays enabled — preserves the dev / SSH-tunnel-only flow.
		if authCfg.Enabled() && authToken == "" {
			mOpen.Disable()
		}
		systray.AddSeparator()
		mDCs := systray.AddMenuItem("Datacenters", "Per-datacenter health")
		mDCs.Disable()
		// "Switch cluster" submenu — only useful when the config
		// declares more than one cluster. Each item calls
		// sh.SwitchCluster(name) ; the supervisor's reselect emits a
		// Switch event that propagates to the chip + tooltip.
		clusterSwitchers := map[string]*systray.MenuItem{}
		if names := sh.Clusters(); len(names) > 1 {
			mSwitch := systray.AddMenuItem("Switch cluster", "Federated clusters — pick which one the WebView reads from")
			for _, name := range names {
				clusterSwitchers[name] = mSwitch.AddSubMenuItem(name, "Switch the WebView to "+name)
			}
		}
		systray.AddSeparator()
		// "Sign in" and "Sign out" are only meaningful when auth is
		// configured. Visibility depends on whether a non-expired
		// token is currently in our in-memory cache : signed in →
		// Sign out visible, signed out → Sign in visible. The toggle
		// is driven by the click handlers below.
		var mSignIn, mSignOut *systray.MenuItem
		if authCfg.Enabled() {
			mSignIn = systray.AddMenuItem("Sign in", "Open the auth window and sign in to the cluster")
			mSignOut = systray.AddMenuItem("Sign out", "Forget the cached session and re-authenticate")
			if authToken == "" {
				mSignOut.Hide()
			} else {
				mSignIn.Hide()
			}
			systray.AddSeparator()
		}
		mQuit := systray.AddMenuItem("Quit", "Quit Weft")

		go refreshStatus(ctx, sh, mDCs, mActive)

		// signInCh / signOutCh are never-firing nil channels when auth
		// isn't configured, so the select below stays valid without an
		// extra branch. Live token is kept in `authToken` (loop-local
		// copy of the arg) so openDashboard always sees the latest.
		var signInCh, signOutCh <-chan struct{}
		if mSignIn != nil {
			signInCh = mSignIn.ClickedCh
		}
		if mSignOut != nil {
			signOutCh = mSignOut.ClickedCh
		}

		// Goroutine per cluster switcher so the main select stays
		// clean. Each goroutine forwards its clicks into a single
		// channel the main loop reads ; cluster name flows alongside
		// so we can call sh.SwitchCluster with it.
		switchCh := make(chan string, len(clusterSwitchers))
		for name, item := range clusterSwitchers {
			name := name
			ch := item.ClickedCh
			go func() {
				for {
					select {
					case <-ctx.Done():
						return
					case <-ch:
						switchCh <- name
					}
				}
			}()
		}

		for {
			select {
			case <-ctx.Done():
				systray.Quit()
				return
			case <-mOpen.ClickedCh:
				openDashboard(sh.URL(), controlURL, authToken)
			case name := <-switchCh:
				sh.SwitchCluster(name)
			case <-signInCh:
				if tok, ok := spawnSignInAndReload(authCfg); ok {
					authToken = tok
					if mSignIn != nil {
						mSignIn.Hide()
					}
					if mSignOut != nil {
						mSignOut.Show()
					}
					mOpen.Enable()
				}
			case <-signOutCh:
				if authCfg.Enabled() {
					if err := defaultKeychain().Delete(authCfg.KeychainService, authCfg.KeychainAccount); err != nil {
						log.Printf("weft-app: sign out: %v", err)
					}
				}
				authToken = ""
				if mSignOut != nil {
					mSignOut.Hide()
				}
				if mSignIn != nil {
					mSignIn.Show()
				}
				mOpen.Disable()
			case <-mQuit.ClickedCh:
				systray.Quit()
				return
			}
		}
	}
}

// spawnSignInAndReload runs the auth window in a child process (the
// `--sign-in` mode of this binary) so the WebKit2GTK window's
// main-thread affinity doesn't clash with systray's. Blocks until the
// child exits ; on success the new token is in the Secret Service and
// we read it back into the tray's in-memory cache so openDashboard sees
// it on the very next click. Returns (token, true) on success, ("",
// false) on failure or user-dismissed window.
func spawnSignInAndReload(cfg AuthConfig) (string, bool) {
	exe, err := os.Executable()
	if err != nil {
		log.Printf("weft-app: locate executable: %v", err)
		return "", false
	}
	cmd := exec.Command(exe, "--sign-in")
	cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr
	if err := cmd.Run(); err != nil {
		log.Printf("weft-app: sign in subprocess: %v", err)
		return "", false
	}
	tok, ok, err := defaultKeychain().Get(cfg.KeychainService, cfg.KeychainAccount)
	if err != nil || !ok || tok.Expired() || tok.Bearer() == "" {
		log.Printf("weft-app: sign in subprocess returned but no usable token in secret service (err=%v ok=%v)", err, ok)
		return "", false
	}
	return tok.Bearer(), true
}

// refreshStatus mirrors the supervisor's per-DC health into submenu
// items (● healthy / ○ down, with " — active" suffix on the selected
// DC). It also pushes the active DC's name into the tray tooltip + the
// top-of-menu active label so it's visible without opening the menu.
func refreshStatus(ctx context.Context, sh *shell.Shell, parent, activeLabel *systray.MenuItem) {
	// "<cluster>|<dc>" -> tray entry. Per-cluster headers (disabled
	// items used as section separators) are keyed by "@<cluster>".
	items := map[string]*systray.MenuItem{}
	lastActive := ""
	t := time.NewTicker(2 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			activeFull := ""
			for _, st := range sh.Status() {
				// Cluster header once per cluster, before its first DC.
				clusterKey := "@" + st.Cluster
				if st.Cluster != "" {
					if _, ok := items[clusterKey]; !ok {
						hdr := parent.AddSubMenuItem(st.ClusterLabelOrName(), st.Cluster)
						hdr.Disable()
						items[clusterKey] = hdr
					}
				}
				dcKey := st.Cluster + "|" + st.Name
				it, ok := items[dcKey]
				if !ok {
					// Two-space indent so the DC line nests visually
					// under its cluster header.
					it = parent.AddSubMenuItem("  "+st.Label(), st.Target)
					items[dcKey] = it
				}
				mark := "○"
				if st.Health == failover.Up {
					mark = "●"
				}
				title := "  " + mark + " " + st.Label()
				if st.DisplayName != "" && st.DisplayName != st.Name {
					title += " (" + st.Name + ")"
				}
				if st.Active {
					title += " — active"
					activeFull = st.FullLabel()
				}
				it.SetTitle(title)
			}
			if activeFull != lastActive {
				if activeFull == "" {
					systray.SetTooltip("Loom " + version + " — no datacenter reachable")
					activeLabel.SetTitle("Loom " + version + " — no datacenter reachable")
				} else {
					systray.SetTooltip("Loom " + version + " — " + activeFull)
					activeLabel.SetTitle(activeFull)
				}
				lastActive = activeFull
			}
		}
	}
}

// openDashboard spawns this same binary in --dashboard mode, pointed at
// the gateway origin. A separate process so the WebView gets its own
// main run loop (the tray owns this one). authToken is forwarded via
// the WEFT_AUTH_TOKEN env var so the dashboard's WebView fetch
// interceptor stamps Bearer on every API call.
func openDashboard(gatewayURL, controlURL, authToken string) {
	exe, err := os.Executable()
	if err != nil {
		log.Printf("weft-app: locate executable: %v", err)
		return
	}
	cmd := exec.Command(exe, "--dashboard", "--url", gatewayURL, "--control", controlURL)
	cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr
	cmd.Env = os.Environ()
	if authToken != "" {
		cmd.Env = append(cmd.Env, WEFTAuthTokenEnv+"="+authToken)
	}
	if err := cmd.Start(); err != nil {
		log.Printf("weft-app: open dashboard: %v", err)
	}
}
