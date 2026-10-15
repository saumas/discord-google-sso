// Command discord-google-sso runs the self-hosted Discord ↔ Google Workspace
// SSO verification service. Subcommands: `serve` (or no arguments) runs the
// HTTP server, `revoke` is the operator CLI, and `sim-discord`/`sim-google`
// are the E2E provider simulators used by the Kind test suite. Commands are
// dispatched with spf13/cobra; usage failures exit non-zero with cobra's
// error text.
package main

import (
	"context"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/spf13/cobra"

	"github.com/saumas/discord-google-sso/internal/cli"
	"github.com/saumas/discord-google-sso/internal/config"
	"github.com/saumas/discord-google-sso/internal/core"
	"github.com/saumas/discord-google-sso/internal/discordapi"
	"github.com/saumas/discord-google-sso/internal/googleoidc"
	"github.com/saumas/discord-google-sso/internal/kube"
	"github.com/saumas/discord-google-sso/internal/reconciler"
	"github.com/saumas/discord-google-sso/internal/server"
	"github.com/saumas/discord-google-sso/internal/session"
	"github.com/saumas/discord-google-sso/internal/sim"
	"github.com/saumas/discord-google-sso/internal/state"
)

func main() {
	if err := newRootCommand(runServer).Execute(); err != nil {
		os.Exit(1)
	}
}

// newRootCommand builds the command tree: the root's default action runs the
// server (bare invocation and `serve` share one code path via serveFn),
// alongside the operator CLI and the two E2E provider simulators.
func newRootCommand(serveFn func()) *cobra.Command {
	root := &cobra.Command{
		Use:   "discord-google-sso",
		Short: "self-hosted Discord ↔ Google Workspace SSO verification service",
		Run:   func(cmd *cobra.Command, args []string) { serveFn() },
	}
	serve := &cobra.Command{
		Use:   "serve",
		Short: "run the verification HTTP server (default when no arguments are given)",
		Run:   func(cmd *cobra.Command, args []string) { serveFn() },
	}
	root.AddCommand(serve, cli.NewRevokeCommand(), sim.NewDiscordCommand(), sim.NewGoogleCommand())
	return root
}

func runServer() {
	log := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	slog.SetDefault(log)

	cfg, err := config.Load()
	if err != nil {
		log.Error("configuration invalid", "error", err.Error())
		os.Exit(1)
	}

	client, ns, err := kube.Client()
	if err != nil {
		log.Error("kubernetes client", "error", err.Error())
		os.Exit(1)
	}
	// Only fill in the namespace when none was configured: an explicit
	// DGS_NAMESPACE value (including an explicit "default") always wins.
	if cfg.Namespace == "" {
		cfg.Namespace = ns
	}

	store := state.NewStore(client, cfg.Namespace, cfg.StateSecretName, log)

	discord := discordapi.New(cfg.Discord.BaseURL, cfg.Discord.BotToken, cfg.Discord.ClientID, cfg.Discord.ClientSecret, cfg.Discord.CallbackURL, log)
	google := googleoidc.New(cfg.Google.BaseURL, cfg.Google.ClientID, cfg.Google.ClientSecret, cfg.Google.CallbackURL, cfg.ClockLeeway, log)
	sessions := session.NewManager(cfg.SessionTTL)
	svc := core.New(cfg, store, discord, sessions, log)
	httpServer := server.New(cfg, svc, discord, google, sessions, log)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	// Load state (create if missing); validate schema version and guild
	// ownership. Failures are fatal with clear messages.
	if _, err := store.Load(ctx, cfg.GuildID); err != nil {
		log.Error("state secret load failed", "error", err.Error())
		os.Exit(1)
	}
	httpServer.SetReady(true)
	log.Info("service ready", "guild", cfg.GuildID, "namespace", cfg.Namespace, "listen", cfg.ListenAddr)

	// Background: idempotent, guild-scoped /revoke command registration.
	// Failure is non-fatal; retry until it succeeds.
	go func() {
		for {
			if err := discord.RegisterRevokeCommand(ctx, cfg.GuildID); err != nil {
				log.Warn("slash command registration failed; will retry", "error", err.Error())
				select {
				case <-ctx.Done():
					return
				case <-time.After(30 * time.Second):
				}
				continue
			}
			log.Info("slash command registered", "command", discordapi.RevokeCommandName)
			return
		}
	}()

	// Reconciler: startup pass plus interval ticker.
	rec := reconciler.New(svc, cfg.ReconcileInterval)
	go rec.Run(ctx)

	if err := httpServer.ListenAndServe(ctx); err != nil {
		log.Error("http server", "error", err.Error())
		os.Exit(1)
	}
}
