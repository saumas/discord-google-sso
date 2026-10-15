package cli

import "testing"

func TestParseArgs(t *testing.T) {
	cases := []struct {
		name    string
		args    []string
		member  string
		secret  string
		guild   string
		ns      string
		wantErr bool
	}{
		{
			name:   "documented order (positional first)",
			args:   []string{"12345", "--state-secret", "st", "--guild", "90"},
			member: "12345", secret: "st", guild: "90",
		},
		{
			name:   "flags first",
			args:   []string{"--state-secret", "st", "--guild", "90", "12345"},
			member: "12345", secret: "st", guild: "90",
		},
		{
			name:   "interspersed with namespace",
			args:   []string{"--state-secret", "st", "12345", "--namespace", "custom", "--guild", "90"},
			member: "12345", secret: "st", guild: "90", ns: "custom",
		},
		{name: "missing member", args: []string{"--state-secret", "st", "--guild", "90"}, wantErr: true},
		{name: "missing state secret", args: []string{"12345", "--guild", "90"}, wantErr: true},
		{name: "missing guild", args: []string{"12345", "--state-secret", "st"}, wantErr: true},
		{name: "unknown flag", args: []string{"12345", "--state-secret", "st", "--guild", "90", "--evil"}, wantErr: true},
		{name: "flag without value", args: []string{"12345", "--state-secret"}, wantErr: true},
		{name: "two positionals", args: []string{"12345", "67890", "--state-secret", "st", "--guild", "90"}, wantErr: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			member, secret, guild, ns, err := parseArgs(tc.args)
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
