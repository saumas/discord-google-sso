// Command discord-google-sso runs the self-hosted Discord ↔ Google Workspace
// SSO verification service. The default (no arguments) is the server; the
// binary also carries the operator CLI (`revoke`) and the E2E provider
// simulators (`sim-discord`, `sim-google`) used by the Kind test suite.
package main

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
	"time"

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
	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "revoke":
			os.Exit(cli.Revoke(os.Args[2:]))
		case "sim-discord":
			sim.RunDiscord(os.Args[2:])
			return
		case "sim-google":
			sim.RunGoogle(os.Args[2:])
			return
		}
	}
	runServer()
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
	if cfg.Namespace == "" || cfg.Namespace == "default" {
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
	rec := reconciler.New(svc, cfg.ReconcileInterval, log)
	go rec.Run(ctx)

	if err := httpServer.ListenAndServe(ctx); err != nil {
		log.Error("http server", "error", err.Error())
		os.Exit(1)
	}
	_ = fmt.Sprint()
}
