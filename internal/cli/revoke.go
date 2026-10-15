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
	"fmt"
	"os"
	"time"

	"github.com/spf13/cobra"

	"github.com/saumas/discord-google-sso/internal/core"
	"github.com/saumas/discord-google-sso/internal/kube"
	"github.com/saumas/discord-google-sso/internal/state"
)

// NewRevokeCommand constructs the `revoke` subcommand:
//
//	discord-google-sso revoke <member-id> --state-secret <name> --guild <id> [--namespace <ns>]
//
// pflag's interspersed parsing lets flags and the positional member ID
// appear in any order. Usage errors (missing or empty member ID, missing or
// empty required flags, unknown flag) surface as cobra errors with usage
// text; runtime failures print verbatim to stderr. Both exit 1 at the
// process boundary in main.
func NewRevokeCommand() *cobra.Command {
	var stateSecret, guild, namespace string
	cmd := &cobra.Command{
		Use:   "revoke <member-id>",
		Short: "operator CLI: commit a revocation",
		Args:  revokeArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			// Required-flag validation only checks that a flag was set,
			// so an explicitly empty value still reaches this point;
			// reject it here, before any cluster contact.
			if stateSecret == "" {
				return fmt.Errorf("--state-secret must not be empty")
			}
			if guild == "" {
				return fmt.Errorf("--guild must not be empty")
			}
			// Failures past this point are runtime failures, not usage
			// errors: keep the historical wording verbatim (e.g.
			// "state load: ...") and let main() decide the exit code.
			cmd.SilenceUsage = true
			cmd.SilenceErrors = true
			if err := runRevoke(args[0], stateSecret, guild, namespace); err != nil {
				fmt.Fprintln(os.Stderr, err)
				return err
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&stateSecret, "state-secret", "", "name of the state secret")
	cmd.Flags().StringVar(&guild, "guild", "", "Discord guild (server) ID")
	cmd.Flags().StringVar(&namespace, "namespace", "", "namespace of the state secret (default: the service account's namespace)")
	// MarkFlagRequired fails only on an unregistered flag name; the flags
	// above are registered with these same static names.
	_ = cmd.MarkFlagRequired("state-secret")
	_ = cmd.MarkFlagRequired("guild")
	return cmd
}

// revokeArgs enforces exactly one positional member ID and rejects an
// explicitly empty one: the commit path keys revocations by member ID, and
// "" would commit a garbage-keyed epoch and report success.
func revokeArgs(cmd *cobra.Command, args []string) error {
	if err := cobra.ExactArgs(1)(cmd, args); err != nil {
		return err
	}
	if args[0] == "" {
		return fmt.Errorf("member ID must not be empty")
	}
	return nil
}

// runRevoke runs the revocation commit. Runtime failures (Kubernetes
// client, state load, commit) are returned as errors; the command prints
// them verbatim to stderr and the process boundary turns them into exit 1.
func runRevoke(memberID, stateSecret, guild, namespace string) error {
	client, ns, err := kube.Client()
	if err != nil {
		return fmt.Errorf("kubernetes client: %v", err)
	}
	if namespace != "" {
		ns = namespace
	}

	store := state.NewStore(client, ns, stateSecret, nil)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Load first so corrupt state or a foreign guild fails with a clear
	// error rather than resetting anything. An empty guild ID must never
	// reach this point: on a cache miss, Load persists a document owned by
	// the (garbage) guild before validating it.
	if _, err := store.Load(ctx, guild); err != nil {
		return fmt.Errorf("state load: %v", err)
	}

	res, err := core.RevokeCommitOnly(ctx, store, guild, memberID)
	if err != nil {
		return fmt.Errorf("revoke: %v", err)
	}
	fmt.Printf("revocation committed for member %s (epoch %d)\n", memberID, res.Epoch)
	if res.CreatedRestoreOp {
		fmt.Println("role restoration is still pending; the service will apply it automatically")
	} else {
		fmt.Println("no role restoration needed (no verified link or revocation was outstanding)")
	}
	return nil
}
