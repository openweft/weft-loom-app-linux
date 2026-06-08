package main

import (
	"context"
	"log"
	"os"

	webview "github.com/webview/webview_go"

	"github.com/openweft/weft-app-core/control"
	"github.com/openweft/weft-app-core/shell"
	"github.com/openweft/weft-app-core/webinject"
)

// runDashboard shows the dashboard WebKit2GTK window, pointed at the
// gateway origin the tray process exposes. Blocks on the WebView run
// loop (this process's main thread).
func runDashboard(gatewayURL, controlURL string) {
	if gatewayURL == "" {
		log.Fatal("weft-app: --url is required in dashboard mode")
	}

	// No-op on Linux ; WebKit2GTK windows show and activate by default
	// without any policy change. Kept symmetric with the macOS path so
	// the call site doesn't grow a build-tag branch.
	promoteDashboardActivation()

	w := webview.New(false)
	defer w.Destroy()
	w.SetTitle("Loom")
	w.SetSize(1280, 860, webview.HintNone)

	// Seed the Topbar chip with the current DC name (one-shot) so it
	// paints correct on first render — the Watch loop below only fires
	// on the *next* change, leaving the chip empty otherwise.
	initialDC := ""
	if controlURL != "" {
		if a, err := (&control.Client{BaseURL: controlURL}).Get(context.Background()); err == nil {
			// FullLabel returns "Cluster · DC" when both are set
			// (canonical clusters[] shape), just the DC label in
			// legacy single-cluster mode.
			initialDC = a.FullLabel()
		}
	}

	// Tell the SPA about the single, stable gateway origin *before* the
	// bundle loads, so its API client comes up failover-aware (see
	// weft-webui src/lib/endpoints.ts).
	w.Init(webinject.InitScript(webinject.Config{
		Endpoints: []webinject.Endpoint{{Name: "cluster", URL: gatewayURL}},
		CurrentDC: initialDC,
	}))

	// When the parent tray passed an auth token (Authenticate had a
	// valid session, OIDC or OpenPubkey), install the fetch interceptor
	// that stamps `Authorization: Bearer <token>` on every same-origin
	// API call. Same document-start hook — runs before the SPA's API
	// client comes up.
	if tok := os.Getenv(WEFTAuthTokenEnv); tok != "" {
		w.Init(webinject.AuthInterceptor(webinject.AuthConfig{
			Token:      tok,
			Origin:     gatewayURL,
			HeaderName: shell.AuthHeaderName,
			Prefix:     shell.AuthHeaderPrefix,
		}))
	}

	// Watch the tray's control server; when the active DC changes under
	// the (unchanging) gateway origin, raise the SPA's "connection
	// switched" banner. endpoints.ts also pipes the `to` field through
	// to the persistent Topbar chip via the same callback.
	if controlURL != "" {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		cl := &control.Client{BaseURL: controlURL}
		go cl.Watch(ctx, func(prev, cur control.Active) {
			// FullLabel surfaces "Cluster · DC" so the SPA chip stays
			// accurate after a switch.
			js := webinject.FailoverNotice(prev.FullLabel(), cur.FullLabel())
			w.Dispatch(func() { w.Eval(js) })
		})
	}

	w.Navigate(gatewayURL)
	w.Run()
}

// promoteDashboardActivation is a no-op on Linux. The macOS counterpart
// flips the dashboard subprocess from LSUIElement (accessory, no Dock)
// to a regular foreground app so its WKWebView window can claim focus ;
// WebKit2GTK windows show and activate by default, so there's nothing
// to do. Kept as a function so the cross-platform main / runSignIn
// paths can call it without a build-tag branch.
func promoteDashboardActivation() {}
