// Command e2e is the one-command MVP release gate: it builds the container
// image, creates a disposable Kind cluster, installs the Helm chart with
// Go-simulated Discord/Google providers, and runs the full scenario matrix
// with a real browser and cryptographically signed interaction requests.
// It requires no real Google/Discord accounts or cloud credentials.
//
// Usage: make e2e   (or: go run ./e2e [-keep] [-cluster name])
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"time"
)

var (
	flagKeep     = flag.Bool("keep", false, "keep the Kind cluster on success (always kept on failure unless -force-clean)")
	flagCluster  = flag.String("cluster", "discord-google-sso-e2e", "Kind cluster name")
	flagForceDel = flag.Bool("force-clean", false, "delete the cluster even if a scenario fails")
)

func main() {
	flag.Parse()
	started := time.Now()

	env, err := setup(context.Background(), *flagCluster)
	if err != nil {
		fmt.Fprintf(os.Stderr, "setup failed: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("setup complete in %s\n", time.Since(started).Round(time.Second))

	failed := runScenarios(env)

	if failed == 0 {
		fmt.Printf("\nALL SCENARIOS PASSED (%s)\n", time.Since(started).Round(time.Second))
		if *flagKeep {
			fmt.Println("cluster kept (-keep); app:", env.appURL)
		} else {
			env.teardown()
		}
		return
	}
	fmt.Fprintf(os.Stderr, "\n%d SCENARIO(S) FAILED\n", failed)
	if *flagForceDel {
		env.teardown()
	} else {
		fmt.Println("cluster kept for debugging; app:", env.appURL)
		fmt.Println("delete with: kind delete cluster --name", *flagCluster)
	}
	os.Exit(1)
}
