package main

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/chromedp/chromedp"
)

// browser drives the real Chrome browser through the verification flow.
type browser struct {
	ctx    context.Context
	cancel context.CancelFunc
}

func newBrowser(ctx context.Context) (*browser, error) {
	opts := append(chromedp.DefaultExecAllocatorOptions[:],
		chromedp.Flag("disable-gpu", true),
	)
	allocCtx, cancelAlloc := chromedp.NewExecAllocator(ctx, opts...)
	bctx, cancelB := chromedp.NewContext(allocCtx)
	// Warm the browser up. IMPORTANT: the first Do must run on bctx itself,
	// not a derived timeout context — the tab's session listeners bind to
	// the context of the first run, and canceling a derived context would
	// kill the tab for every later action.
	if err := chromedp.Do(bctx, chromedp.Navigate("about:blank")); err != nil {
		cancelB()
		cancelAlloc()
		return nil, fmt.Errorf("launch chrome: %w (is Google Chrome installed?)", err)
	}
	b := &browser{ctx: bctx, cancel: func() { cancelB(); cancelAlloc() }}
	return b, nil
}

func (b *browser) close() { b.cancel() }

type step int

const (
	stepApprove step = iota
	stepDeny
	stepStopAtGoogle // run through the Discord leg only, then stop
)

// waitFor polls the browser location until pred holds or the timeout hits.
func (b *browser) waitFor(ctx context.Context, timeout time.Duration, pred func(url string) bool) error {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		u, err := chromedp.Run(ctx, chromedp.Location())
		if err == nil && pred(u) {
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(150 * time.Millisecond):
		}
	}
	return fmt.Errorf("timed out waiting for navigation")
}

func onHost(prefix string) func(string) bool {
	return func(u string) bool { return strings.HasPrefix(u, prefix) }
}

// notHost matches URLs that are NOT on the given host prefix.
func notHost(prefix string) func(string) bool {
	return func(u string) bool { return !strings.HasPrefix(u, prefix) }
}

func buttonFor(s step) string {
	if s == stepDeny {
		return "#deny"
	}
	return "#approve"
}

// flowSteps drives the browser flow with the given consent decisions and
// returns the final page body text. Navigation is awaited by polling the
// browser location: consent pages and application pages share markup, so
// element-based waits cannot distinguish them.
func (b *browser) flowSteps(env *env, discord, google step) (string, error) {
	ctx, cancel := context.WithTimeout(b.ctx, 90*time.Second)
	defer cancel()

	if err := chromedp.Do(ctx, chromedp.Navigate(env.appURL+"/verify")); err != nil {
		return "", err
	}
	// The app redirects to the Discord authorize page.
	if err := b.waitFor(ctx, 15*time.Second, onHost(env.discURL)); err != nil {
		return "", fmt.Errorf("discord authorize page: %w", err)
	}
	if err := chromedp.Do(ctx,
		chromedp.WaitVisible("#approve"),
		chromedp.Click(buttonFor(discord)),
	); err != nil {
		return "", err
	}
	// The decision posts and redirects to the app callback, which either
	// renders a rejection page or redirects on to Google.
	if err := b.waitFor(ctx, 20*time.Second, notHost(env.discURL)); err != nil {
		return "", fmt.Errorf("post-discord navigation: %w", err)
	}
	if discord == stepDeny {
		return b.bodyText(ctx)
	}
	if discord == stepStopAtGoogle {
		// Park on the Google consent page; wait for the consent form to be
		// actually rendered so a later resume cannot race page commit.
		if err := b.waitFor(ctx, 15*time.Second, onHost(env.googURL)); err != nil {
			return "", fmt.Errorf("google authorize page: %w", err)
		}
		if err := chromedp.Do(ctx, chromedp.WaitVisible("#approve")); err != nil {
			return "", fmt.Errorf("google consent page render: %w", err)
		}
		return "", nil
	}
	// Either the Google consent page is showing, or the flow already ended
	// on an application page (e.g. non-member rejection).
	if err := b.waitFor(ctx, 15*time.Second, func(u string) bool {
		return strings.HasPrefix(u, env.googURL) || strings.HasPrefix(u, env.appURL)
	}); err != nil {
		return "", fmt.Errorf("landing after discord leg: %w", err)
	}
	u, err := chromedp.Run(ctx, chromedp.Location())
	if err != nil {
		return "", err
	}
	if strings.HasPrefix(u, env.appURL) {
		return b.bodyText(ctx)
	}
	if err := chromedp.Do(ctx,
		chromedp.WaitVisible("#approve"),
		chromedp.Click(buttonFor(google)),
	); err != nil {
		return "", err
	}
	if err := b.waitFor(ctx, 20*time.Second, notHost(env.googURL)); err != nil {
		return "", fmt.Errorf("post-google navigation: %w", err)
	}
	if err := b.waitFor(ctx, 15*time.Second, onHost(env.appURL)); err != nil {
		return "", fmt.Errorf("final page: %w", err)
	}
	return b.bodyText(ctx)
}

// verifyFlow drives the full browser flow for the currently simulated logins
// and returns the final page body text.
func (b *browser) verifyFlow(env *env) string {
	body, err := b.flowSteps(env, stepApprove, stepApprove)
	if err != nil {
		return "FLOW-ERROR: " + err.Error()
	}
	return body
}

func (b *browser) bodyText(ctx context.Context) (string, error) {
	return chromedp.Run(ctx, chromedp.Text("body"))
}

// clickButtonJS submits the consent form via a DOM click, which does not
// depend on the page receiving compositor frames (a parked headless page can
// stall coordinate-based mouse clicks).
func (b *browser) clickButtonJS(ctx context.Context, id string) error {
	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		ready, err := chromedp.Run(ctx, chromedp.Evaluate[bool](`!!document.getElementById('`+id+`')`))
		if err != nil {
			return err
		}
		if ready {
			_, err := chromedp.Run(ctx, chromedp.Evaluate[any](`document.getElementById('`+id+`').click()`))
			return err
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(100 * time.Millisecond):
		}
	}
	return fmt.Errorf("button #%s never appeared", id)
}

// continueFromGoogleConsent resumes a flow that stopped at the Google
// consent page and returns the final page body.
func (b *browser) continueFromGoogleConsent(env *env) (string, error) {
	ctx, cancel := context.WithTimeout(b.ctx, 60*time.Second)
	defer cancel()
	if err := b.clickButtonJS(ctx, "approve"); err != nil {
		return "", fmt.Errorf("continue from google consent: %w", err)
	}
	if err := b.waitFor(ctx, 20*time.Second, notHost(env.googURL)); err != nil {
		return "", fmt.Errorf("post-google navigation: %w", err)
	}
	if err := b.waitFor(ctx, 15*time.Second, onHost(env.appURL)); err != nil {
		return "", fmt.Errorf("final page: %w", err)
	}
	return b.bodyText(ctx)
}

// currentURL returns the browser's current location.
func (b *browser) currentURL() (string, error) {
	ctx, cancel := context.WithTimeout(b.ctx, 10*time.Second)
	defer cancel()
	return chromedp.Run(ctx, chromedp.Location())
}

// navigateTo opens a URL and returns the resulting page body.
func (b *browser) navigateTo(u string) (string, error) {
	ctx, cancel := context.WithTimeout(b.ctx, 30*time.Second)
	defer cancel()
	err := chromedp.Do(ctx, chromedp.Navigate(u))
	if err != nil && strings.Contains(err.Error(), "ERR_ABORTED") {
		// Navigation racing a pending load; retry once.
		err = chromedp.Do(ctx, chromedp.Navigate(u))
	}
	if err != nil {
		return "", err
	}
	return b.bodyText(ctx)
}

func httpGetNoFollow(url string) (*http.Response, error) {
	c := &http.Client{Timeout: 5 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}}
	return c.Get(url)
}
