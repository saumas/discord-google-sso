package sim

import (
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
)

// RunDiscord runs the Discord simulator as a standalone process (used by the
// E2E suite as an in-cluster Deployment).
func RunDiscord(args []string) {
	fs := flag.NewFlagSet("sim-discord", flag.ExitOnError)
	addr := fs.String("addr", ":8080", "listen address")
	clientID := fs.String("client-id", "sim-discord-client", "OAuth client ID")
	clientSecret := fs.String("client-secret", "sim-discord-secret", "OAuth client secret")
	redirectURI := fs.String("redirect-uri", "http://localhost:8080/callback/discord", "registered redirect URI")
	botToken := fs.String("bot-token", "sim-bot-token", "bot token")
	_ = fs.Parse(args)

	log := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	d := NewDiscordSim(*clientID, *clientSecret, *redirectURI, *botToken, log)
	log.Info("discord simulator listening", "addr", *addr)
	if err := http.ListenAndServe(*addr, d.Handler()); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

// RunGoogle runs the Google OIDC simulator as a standalone process.
func RunGoogle(args []string) {
	fs := flag.NewFlagSet("sim-google", flag.ExitOnError)
	addr := fs.String("addr", ":8080", "listen address")
	issuer := fs.String("issuer", "http://localhost:8080", "issuer / base URL advertised in discovery")
	clientID := fs.String("client-id", "sim-google-client", "OAuth client ID")
	clientSecret := fs.String("client-secret", "sim-google-secret", "OAuth client secret")
	redirectURI := fs.String("redirect-uri", "http://localhost:8080/callback/google", "registered redirect URI")
	_ = fs.Parse(args)

	log := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	g, err := NewGoogleSim(*issuer, *clientID, *clientSecret, *redirectURI, log)
	if err != nil {
		fmt.Fprintf(os.Stderr, "sim-google: %v\n", err)
		os.Exit(1)
	}
	log.Info("google simulator listening", "addr", *addr)
	if err := http.ListenAndServe(*addr, g.Handler()); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
