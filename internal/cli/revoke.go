// Package cli implements the operator CLI. It is a subcommand of the same
// binary, running as a separate process (typically a Job) against the
// cluster. It is commit-only: it performs the core Revoke's atomic state
// commit and reports the commit plus any still-pending role restoration; it
// holds no Discord credentials and no role policy — role restoration is
// applied by the service's reconciler through the durable revocation
// operation.
package cli

import (
	"context"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/saumas/discord-google-sso/internal/core"
	"github.com/saumas/discord-google-sso/internal/kube"
	"github.com/saumas/discord-google-sso/internal/state"
)

// Revoke runs the `revoke` subcommand.
//
// Usage:
//
//	discord-google-sso revoke <member-id> --state-secret <name> --guild <id> [--namespace <ns>]
func Revoke(args []string) int {
	fs := flag.NewFlagSet("revoke", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	stateSecret := fs.String("state-secret", "", "name of the app-owned state Secret")
	guild := fs.String("guild", "", "expected guild ID (safety check against the state document)")
	namespace := fs.String("namespace", "", "namespace of the state Secret (defaults to this pod's namespace)")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if fs.NArg() != 1 || *stateSecret == "" || *guild == "" {
		fmt.Fprintln(os.Stderr, "usage: discord-google-sso revoke <member-id> --state-secret <name> --guild <id> [--namespace <ns>]")
		return 2
	}
	memberID := fs.Arg(0)

	client, ns, err := kube.Client()
	if err != nil {
		fmt.Fprintf(os.Stderr, "kubernetes client: %v\n", err)
		return 1
	}
	if *namespace != "" {
		ns = *namespace
	}

	store := state.NewStore(client, ns, *stateSecret, nil)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Load first so corrupt state or a foreign guild fails with a clear
	// error rather than resetting anything.
	if _, err := store.Load(ctx, *guild); err != nil {
		fmt.Fprintf(os.Stderr, "state load: %v\n", err)
		return 1
	}

	res, err := core.RevokeCommitOnly(ctx, store, *guild, memberID, nil)
	if err != nil {
		fmt.Fprintf(os.Stderr, "revoke: %v\n", err)
		return 1
	}
	fmt.Printf("revocation committed for member %s (epoch %d)\n", memberID, res.Epoch)
	if res.CreatedRestoreOp {
		fmt.Println("role restoration is still pending; the service will apply it automatically")
	} else {
		fmt.Println("no role restoration needed (no verified link or revocation was outstanding)")
	}
	return 0
}
