package main

import (
	"context"
	"fmt"
	"net/http"
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
	// Warm the browser up (first run launches the process).
	tctx, cancelT := context.WithTimeout(bctx, 60*time.Second)
	defer cancelT()
	if err := chromedp.Do(tctx, chromedp.Navigate("about:blank")); err != nil {
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

// flowSteps drives the browser flow with the given consent decisions and
// returns the final page body text.
func (b *browser) flowSteps(env *env, discord, google step) (string, error) {
	ctx, cancel := context.WithTimeout(b.ctx, 90*time.Second)
	defer cancel()

	steps := []chromedp.Action[chromedp.Void]{chromedp.Navigate(env.appURL + "/verify")}
	switch discord {
	case stepDeny:
		steps = append(steps,
			chromedp.WaitVisible("#deny"),
			chromedp.Click("#deny"),
			chromedp.WaitVisible("h1"),
		)
		if err := chromedp.Do(ctx, steps...); err != nil {
			return "", err
		}
		return b.bodyText(ctx)
	case stepApprove, stepStopAtGoogle:
		steps = append(steps,
			chromedp.WaitVisible("#approve"),
			chromedp.Click("#approve"),
		)
	}
	if discord == stepStopAtGoogle {
		// Wait until the Google consent page is showing, then stop.
		steps = append(steps, chromedp.WaitVisible("#approve"))
		return "", chromedp.Do(ctx, steps...)
	}

	switch google {
	case stepDeny:
		steps = append(steps,
			chromedp.WaitVisible("#deny"),
			chromedp.Click("#deny"),
		)
	case stepApprove:
		steps = append(steps,
			chromedp.WaitVisible("#approve"),
			chromedp.Click("#approve"),
		)
	}
	steps = append(steps, chromedp.WaitVisible("h1"))
	if err := chromedp.Do(ctx, steps...); err != nil {
		return "", err
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

// continueFromGoogleConsent resumes a flow that stopped at the Google
// consent page and returns the final page body.
func (b *browser) continueFromGoogleConsent() (string, error) {
	ctx, cancel := context.WithTimeout(b.ctx, 90*time.Second)
	defer cancel()
	if err := chromedp.Do(ctx,
		chromedp.WaitVisible("#approve"),
		chromedp.Click("#approve"),
		chromedp.WaitVisible("h1"),
	); err != nil {
		return "", err
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
	if err := chromedp.Do(ctx,
		chromedp.Navigate(u),
		chromedp.WaitVisible("h1"),
	); err != nil {
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
