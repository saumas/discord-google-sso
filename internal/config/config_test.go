package config

import (
	"strings"
	"testing"
)

func setenv(t *testing.T, k, v string) {
	t.Helper()
	t.Setenv(EnvPrefix+k, v)
}

func validEnv(t *testing.T) {
	t.Helper()
	setenv(t, "GUILD_ID", "12345")
	setenv(t, "PUBLIC_BASE_URL", "https://sso.example.com")
	setenv(t, "DISCORD_CLIENT_ID", "dclid")
	setenv(t, "DISCORD_CLIENT_SECRET", "dsecret")
	setenv(t, "DISCORD_BOT_TOKEN", "bottoken")
	setenv(t, "DISCORD_PUBLIC_KEY", strings.Repeat("ab", 32)) // 64 hex chars = 32 bytes
	setenv(t, "GOOGLE_CLIENT_ID", "gclid")
	setenv(t, "GOOGLE_CLIENT_SECRET", "gsecret")
	setenv(t, "ALLOWED_DOMAINS", "example.com,other.org")
	setenv(t, "ADD_ROLES", "111,222")
	setenv(t, "REMOVE_ROLES", "333")
	setenv(t, "UNVERIFIED_ROLES", "444")
	setenv(t, "ADMIN_ROLE_IDS", "555")
}

func TestLoadValid(t *testing.T) {
	validEnv(t)
	c, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if c.Discord.CallbackURL != "https://sso.example.com/callback/discord" {
		t.Fatalf("callback derived wrong: %s", c.Discord.CallbackURL)
	}
}

func TestLoadRejectsInvalidConfig(t *testing.T) {
	cases := []struct {
		name, key, value string
	}{
		{"missing bot token", "DISCORD_BOT_TOKEN", ""},
		{"malformed public key", "DISCORD_PUBLIC_KEY", "zzzz"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			validEnv(t)
			setenv(t, tc.key, tc.value)
			if _, err := Load(); err == nil {
				t.Fatalf("%s accepted", tc.name)
			}
		})
	}
}

func TestRolePolicyDisjointness(t *testing.T) {
	cases := []struct {
		name                          string
		add, remove, unverified, want string
	}{
		{"should reject when a granted role is also removed", "111", "111", "222", "granted and removed"},
		{"should reject when a granted role is in the unverified set", "111", "333", "111", "initial/unverified"},
		{"should accept disjoint role sets", "111", "333", "222", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			validEnv(t)
			setenv(t, "ADD_ROLES", tc.add)
			setenv(t, "REMOVE_ROLES", tc.remove)
			setenv(t, "UNVERIFIED_ROLES", tc.unverified)
			_, err := Load()
			if tc.want == "" && err != nil {
				t.Fatalf("unexpected: %v", err)
			}
			if tc.want != "" && (err == nil || !strings.Contains(err.Error(), tc.want)) {
				t.Fatalf("expected error containing %q, got %v", tc.want, err)
			}
		})
	}
}
