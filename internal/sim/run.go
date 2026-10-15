package sim

import (
	"fmt"
	"log/slog"
	"net/http"
	"os"

	"github.com/spf13/cobra"
)

// NewDiscordCommand constructs the `sim-discord` subcommand, running the
// Discord provider simulator as a standalone process (used by the E2E suite
// as an in-cluster Deployment).
func NewDiscordCommand() *cobra.Command {
	var addr, clientID, clientSecret, redirectURI, botToken string
	cmd := &cobra.Command{
		Use:   "sim-discord",
		Short: "run the Discord provider simulator (E2E only)",
		RunE: func(cmd *cobra.Command, args []string) error {
			// A listen failure is a runtime failure, not a usage error.
			cmd.SilenceUsage = true
			cmd.SilenceErrors = true
			log := slog.New(slog.NewJSONHandler(os.Stdout, nil))
			d := NewDiscordSim(clientID, clientSecret, redirectURI, botToken, log)
			log.Info("discord simulator listening", "addr", addr)
			if err := http.ListenAndServe(addr, d.Handler()); err != nil {
				fmt.Fprintln(os.Stderr, err)
				return err
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&addr, "addr", ":8080", "listen address")
	cmd.Flags().StringVar(&clientID, "client-id", "sim-discord-client", "OAuth client ID")
	cmd.Flags().StringVar(&clientSecret, "client-secret", "sim-discord-secret", "OAuth client secret")
	cmd.Flags().StringVar(&redirectURI, "redirect-uri", "http://localhost:8080/callback/discord", "registered redirect URI")
	cmd.Flags().StringVar(&botToken, "bot-token", "sim-bot-token", "bot token")
	return cmd
}

// NewGoogleCommand constructs the `sim-google` subcommand, running the Google
// OIDC provider simulator as a standalone process.
func NewGoogleCommand() *cobra.Command {
	var addr, issuer, clientID, clientSecret, redirectURI string
	cmd := &cobra.Command{
		Use:   "sim-google",
		Short: "run the Google OIDC provider simulator (E2E only)",
		RunE: func(cmd *cobra.Command, args []string) error {
			// Construction and listen failures are runtime failures,
			// not usage errors.
			cmd.SilenceUsage = true
			cmd.SilenceErrors = true
			log := slog.New(slog.NewJSONHandler(os.Stdout, nil))
			g, err := NewGoogleSim(issuer, clientID, clientSecret, redirectURI, log)
			if err != nil {
				fmt.Fprintf(os.Stderr, "sim-google: %v\n", err)
				return err
			}
			log.Info("google simulator listening", "addr", addr)
			if err := http.ListenAndServe(addr, g.Handler()); err != nil {
				fmt.Fprintln(os.Stderr, err)
				return err
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&addr, "addr", ":8080", "listen address")
	cmd.Flags().StringVar(&issuer, "issuer", "http://localhost:8080", "issuer / base URL advertised in discovery")
	cmd.Flags().StringVar(&clientID, "client-id", "sim-google-client", "OAuth client ID")
	cmd.Flags().StringVar(&clientSecret, "client-secret", "sim-google-secret", "OAuth client secret")
	cmd.Flags().StringVar(&redirectURI, "redirect-uri", "http://localhost:8080/callback/google", "registered redirect URI")
	return cmd
}
