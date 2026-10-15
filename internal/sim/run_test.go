package sim

import (
	"io"
	"maps"
	"testing"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
)

// execSimCommand executes a sim command with its run body stubbed out (the
// real body starts an HTTP listener) and returns the command's registered
// flag values — captured via VisitAll so any flag added later is included
// automatically — and the execution error.
func execSimCommand(t *testing.T, cmd *cobra.Command, args []string) (vals map[string]string, err error) {
	t.Helper()
	vals = map[string]string{}
	cmd.RunE = func(c *cobra.Command, a []string) error {
		c.Flags().VisitAll(func(f *pflag.Flag) {
			vals[f.Name] = f.Value.String()
		})
		return nil
	}
	cmd.SetOut(io.Discard)
	cmd.SetErr(io.Discard)
	cmd.SilenceUsage = true
	cmd.SilenceErrors = true
	cmd.SetArgs(args)
	return vals, cmd.Execute()
}

// assertSimFlags checks every expected flag value and rejects any flag
// registered beyond the expected surface (cobra's own "help" excepted).
func assertSimFlags(t *testing.T, vals, want map[string]string) {
	t.Helper()
	for name, w := range want {
		if vals[name] != w {
			t.Errorf("flag --%s = %q, want %q", name, vals[name], w)
		}
	}
	for name := range vals {
		if _, ok := want[name]; !ok && name != "help" {
			t.Errorf("unexpected flag --%s registered", name)
		}
	}
}

func TestDiscordCommand(t *testing.T) {
	// Defaults must match the pre-cobra flag.FlagSet surface verbatim: the
	// E2E Deployments and any scripted invocations rely on them.
	defaults := map[string]string{
		"addr":          ":8080",
		"client-id":     "sim-discord-client",
		"client-secret": "sim-discord-secret",
		"redirect-uri":  "http://localhost:8080/callback/discord",
		"bot-token":     "sim-bot-token",
	}
	cases := []struct {
		name    string
		args    []string
		changed map[string]string // expected deviations from the defaults
		wantErr bool
	}{
		{name: "applies defaults with no arguments", args: []string{}},
		{
			name:    "flag overrides keep untouched defaults",
			args:    []string{"--addr", ":9999", "--client-id", "cid", "--bot-token", "tok"},
			changed: map[string]string{"addr": ":9999", "client-id": "cid", "bot-token": "tok"},
		},
		{name: "rejects unknown flag", args: []string{"--evil"}, wantErr: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			vals, err := execSimCommand(t, NewDiscordCommand(), tc.args)
			if tc.wantErr {
				if err == nil {
					t.Fatal("expected error")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			want := maps.Clone(defaults)
			maps.Copy(want, tc.changed)
			assertSimFlags(t, vals, want)
		})
	}
}

func TestGoogleCommand(t *testing.T) {
	// Defaults must match the pre-cobra flag.FlagSet surface verbatim: the
	// E2E Deployments and any scripted invocations rely on them.
	defaults := map[string]string{
		"addr":          ":8080",
		"issuer":        "http://localhost:8080",
		"client-id":     "sim-google-client",
		"client-secret": "sim-google-secret",
		"redirect-uri":  "http://localhost:8080/callback/google",
	}
	cases := []struct {
		name    string
		args    []string
		changed map[string]string // expected deviations from the defaults
		wantErr bool
	}{
		{name: "applies defaults with no arguments", args: []string{}},
		{
			name:    "flag overrides keep untouched defaults",
			args:    []string{"--addr", ":9999", "--issuer", "https://issuer.example"},
			changed: map[string]string{"addr": ":9999", "issuer": "https://issuer.example"},
		},
		{name: "rejects unknown flag", args: []string{"--evil"}, wantErr: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			vals, err := execSimCommand(t, NewGoogleCommand(), tc.args)
			if tc.wantErr {
				if err == nil {
					t.Fatal("expected error")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			want := maps.Clone(defaults)
			maps.Copy(want, tc.changed)
			assertSimFlags(t, vals, want)
		})
	}
}

// TestSimCommandListenFailureReturnsError runs the real (unstubbed) run body
// against an unlistenable address: the failure must return an error through
// Execute rather than exiting the process, keeping the failure path
// testable in-process.
func TestSimCommandListenFailureReturnsError(t *testing.T) {
	for _, cmd := range []*cobra.Command{NewDiscordCommand(), NewGoogleCommand()} {
		cmd.SetOut(io.Discard)
		cmd.SetErr(io.Discard)
		cmd.SilenceUsage = true
		cmd.SilenceErrors = true
		cmd.SetArgs([]string{"--addr", "not-an-address"})
		if err := cmd.Execute(); err == nil {
			t.Errorf("%s: expected listen error", cmd.Name())
		}
	}
}
