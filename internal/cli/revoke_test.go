package cli

import (
	"io"
	"testing"

	"github.com/spf13/cobra"
)

// execRevokeCommand executes the revoke command against args. Success cases
// get the run body replaced by a value-capturing stub (the real body talks
// to the cluster — that path is covered by the E2E suite); error cases run
// the real body, which is safe because every case in the matrix fails
// validation before any cluster contact.
func execRevokeCommand(t *testing.T, args []string, stub bool) (member, secret, guild, ns string, err error) {
	t.Helper()
	cmd := NewRevokeCommand()
	if stub {
		cmd.RunE = func(c *cobra.Command, a []string) error {
			member = a[0]
			secret, _ = c.Flags().GetString("state-secret")
			guild, _ = c.Flags().GetString("guild")
			ns, _ = c.Flags().GetString("namespace")
			return nil
		}
	}
	cmd.SetOut(io.Discard)
	cmd.SetErr(io.Discard)
	cmd.SilenceUsage = true
	cmd.SilenceErrors = true
	cmd.SetArgs(args)
	return member, secret, guild, ns, cmd.Execute()
}

func TestRevokeCommandArgs(t *testing.T) {
	cases := []struct {
		name    string
		args    []string
		member  string
		secret  string
		guild   string
		ns      string
		wantErr bool
	}{
		{name: "parses documented order (positional first)", args: []string{"12345", "--state-secret", "st", "--guild", "90"}, member: "12345", secret: "st", guild: "90"},
		{name: "parses flags before the positional", args: []string{"--state-secret", "st", "--guild", "90", "12345"}, member: "12345", secret: "st", guild: "90"},
		{name: "parses interspersed flags with namespace", args: []string{"--state-secret", "st", "12345", "--namespace", "custom", "--guild", "90"}, member: "12345", secret: "st", guild: "90", ns: "custom"},
		{name: "parses equals-form flags", args: []string{"--state-secret=st", "--guild=90", "--namespace=custom", "12345"}, member: "12345", secret: "st", guild: "90", ns: "custom"},
		// Explicitly empty values pass MarkFlagRequired, which only checks
		// that the flag was changed; the real run body must reject them.
		{name: "rejects empty member ID", args: []string{"", "--state-secret", "st", "--guild", "90"}, wantErr: true},
		{name: "rejects empty state secret", args: []string{"12345", "--state-secret", "", "--guild", "90"}, wantErr: true},
		{name: "rejects empty guild", args: []string{"12345", "--state-secret", "st", "--guild", ""}, wantErr: true},
		{name: "rejects empty state secret in equals form", args: []string{"--state-secret=", "--guild=90", "12345"}, wantErr: true},
		{name: "rejects empty guild in equals form", args: []string{"--state-secret=st", "--guild=", "12345"}, wantErr: true},
		{name: "rejects missing member ID", args: []string{"--state-secret", "st", "--guild", "90"}, wantErr: true},
		{name: "rejects missing state secret", args: []string{"12345", "--guild", "90"}, wantErr: true},
		{name: "rejects missing guild", args: []string{"12345", "--state-secret", "st"}, wantErr: true},
		{name: "rejects unknown flag", args: []string{"12345", "--state-secret", "st", "--guild", "90", "--evil"}, wantErr: true},
		{name: "rejects flag without value", args: []string{"12345", "--state-secret"}, wantErr: true},
		{name: "rejects multiple member IDs", args: []string{"12345", "67890", "--state-secret", "st", "--guild", "90"}, wantErr: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			member, secret, guild, ns, err := execRevokeCommand(t, tc.args, !tc.wantErr)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("expected error, got member=%q secret=%q guild=%q", member, secret, guild)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if member != tc.member || secret != tc.secret || guild != tc.guild || ns != tc.ns {
				t.Fatalf("got member=%q secret=%q guild=%q ns=%q, want %q/%q/%q/%q",
					member, secret, guild, ns, tc.member, tc.secret, tc.guild, tc.ns)
			}
		})
	}
}
