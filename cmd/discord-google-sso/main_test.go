package main

import (
	"io"
	"testing"

	"github.com/spf13/cobra"
)

// newTestRoot builds a root command whose server action records invocation
// instead of running the real server, with cobra's output discarded.
func newTestRoot(t *testing.T, served *bool) *cobra.Command {
	t.Helper()
	root := newRootCommand(func() { *served = true })
	root.SetOut(io.Discard)
	root.SetErr(io.Discard)
	root.SilenceUsage = true
	root.SilenceErrors = true
	return root
}

func TestRootCommandDispatch(t *testing.T) {
	cases := []struct {
		name       string
		args       []string
		wantErr    bool
		wantServed bool
	}{
		{name: "bare invocation runs the server (default action)", args: []string{}, wantServed: true},
		{name: "serve runs the server", args: []string{"serve"}, wantServed: true},
		{name: "help prints and exits clean", args: []string{"--help"}},
		{name: "subcommand help prints and exits clean", args: []string{"revoke", "--help"}},
		{name: "unknown command fails without running the server", args: []string{"frobnicate"}, wantErr: true},
		{name: "unknown flag on serve fails without running the server", args: []string{"serve", "--bad"}, wantErr: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			served := false
			root := newTestRoot(t, &served)
			root.SetArgs(tc.args)
			err := root.Execute()
			if gotErr := err != nil; gotErr != tc.wantErr {
				t.Fatalf("Execute error = %v, want error: %v", err, tc.wantErr)
			}
			if served != tc.wantServed {
				t.Errorf("server ran = %v, want %v", served, tc.wantServed)
			}
		})
	}
}

// TestRootCommandTree asserts the exposed surface: exactly the documented
// subcommands plus cobra's defaults (completion, help).
func TestRootCommandTree(t *testing.T) {
	served := false
	root := newTestRoot(t, &served)
	// help and completion are added lazily at execution time; initialize
	// them the way Execute() would so the full surface is asserted.
	root.InitDefaultHelpCmd()
	root.InitDefaultCompletionCmd()
	want := map[string]bool{
		"serve": false, "revoke": false, "sim-discord": false, "sim-google": false,
		"completion": false, "help": false,
	}
	for _, cmd := range root.Commands() {
		if _, ok := want[cmd.Name()]; !ok {
			t.Errorf("unexpected subcommand %q", cmd.Name())
		}
		want[cmd.Name()] = true
	}
	for name, found := range want {
		if !found {
			t.Errorf("missing subcommand %q", name)
		}
	}
}
