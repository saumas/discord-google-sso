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
	"strings"
	"time"

	"github.com/saumas/discord-google-sso/internal/core"
	"github.com/saumas/discord-google-sso/internal/kube"
	"github.com/saumas/discord-google-sso/internal/state"
)

// usage prints the invocation help.
const usage = "usage: discord-google-sso revoke <member-id> --state-secret <name> --guild <id> [--namespace <ns>]"

// parseArgs accepts flags and the positional member ID in any order (the
// Go flag package would require flags before positionals, which is a trap
// for copy-pasted invocations).
func parseArgs(args []string) (memberID, stateSecret, guild, namespace string, err error) {
	for i := 0; i < len(args); i++ {
		a := args[i]
		switch {
		case a == "--state-secret", a == "--guild", a == "--namespace":
			if i+1 >= len(args) {
				return "", "", "", "", fmt.Errorf("%s requires a value\n%s", a, usage)
			}
			switch a {
			case "--state-secret":
				stateSecret = args[i+1]
			case "--guild":
				guild = args[i+1]
			case "--namespace":
				namespace = args[i+1]
			}
			i++
		case strings.HasPrefix(a, "--"):
			return "", "", "", "", fmt.Errorf("unknown flag %s\n%s", a, usage)
		default:
			if memberID != "" {
				return "", "", "", "", fmt.Errorf("multiple member IDs given\n%s", usage)
			}
			memberID = a
		}
	}
	if memberID == "" || stateSecret == "" || guild == "" {
		return "", "", "", "", fmt.Errorf("%s", usage)
	}
	return memberID, stateSecret, guild, namespace, nil
}

// Revoke runs the `revoke` subcommand.
//
// Usage:
//
//	discord-google-sso revoke <member-id> --state-secret <name> --guild <id> [--namespace <ns>]
func Revoke(args []string) int {
	memberID, stateSecret, guild, namespace, err := parseArgs(args)
	if err != nil {
		fmt.Fprintln(os.Stderr, err.Error())
		return 2
	}

	client, ns, err := kube.Client()
	if err != nil {
		fmt.Fprintf(os.Stderr, "kubernetes client: %v\n", err)
		return 1
	}
	if namespace != "" {
		ns = namespace
	}

	store := state.NewStore(client, ns, stateSecret, nil)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Load first so corrupt state or a foreign guild fails with a clear
	// error rather than resetting anything.
	if _, err := store.Load(ctx, guild); err != nil {
		fmt.Fprintf(os.Stderr, "state load: %v\n", err)
		return 1
	}

	res, err := core.RevokeCommitOnly(ctx, store, guild, memberID)
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
