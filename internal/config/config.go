// Package config loads and validates service configuration from environment
// variables. Configuration is validated at startup; failures are fatal with
// clear messages.
package config

import (
	"encoding/hex"
	"fmt"
	"net/url"
	"os"
	"slices"
	"strconv"
	"strings"
	"time"
)

// EnvPrefix is the common prefix for all environment variables.
const EnvPrefix = "DGS_"

// Config is the fully validated service configuration.
type Config struct {
	GuildID       string
	PublicBaseURL string
	ListenAddr    string

	Discord struct {
		BaseURL      string // default: https://discord.com
		ClientID     string // also the application ID
		ClientSecret string
		CallbackURL  string
		BotToken     string
		PublicKey    string // hex-encoded Ed25519 public key for interaction verification
	}

	Google struct {
		BaseURL        string // default: https://accounts.google.com
		ClientID       string
		ClientSecret   string
		CallbackURL    string
		AllowedDomains []string
	}

	// Role policy.
	AddRoles        []string // roles granted on verification
	RemoveRoles     []string // roles removed on verification
	UnverifiedRoles []string // configured initial role set for unverified members

	AdminRoleIDs []string
	AdminUserIDs []string

	StateSecretName string
	Namespace       string

	ReconcileInterval time.Duration
	SessionTTL        time.Duration
	ClockLeeway       time.Duration
}

func env(key, def string) string {
	if v, ok := os.LookupEnv(EnvPrefix + key); ok && strings.TrimSpace(v) != "" {
		return strings.TrimSpace(v)
	}
	return def
}

func envList(key string) []string {
	v := strings.TrimSpace(os.Getenv(EnvPrefix + key))
	if v == "" {
		return nil
	}
	var out []string
	for _, part := range strings.Split(v, ",") {
		if p := strings.TrimSpace(part); p != "" {
			out = append(out, p)
		}
	}
	return out
}

func envDur(key string, def time.Duration) (time.Duration, error) {
	v := env(key, "")
	if v == "" {
		return def, nil
	}
	d, err := time.ParseDuration(v)
	if err != nil {
		return 0, fmt.Errorf("%s%s: %w", EnvPrefix, key, err)
	}
	return d, nil
}

// Load reads configuration from the environment and validates it.
func Load() (*Config, error) {
	c := &Config{}
	c.GuildID = env("GUILD_ID", "")
	c.PublicBaseURL = env("PUBLIC_BASE_URL", "")
	c.ListenAddr = env("LISTEN_ADDR", ":8080")

	c.Discord.BaseURL = env("DISCORD_BASE_URL", "https://discord.com")
	c.Discord.ClientID = env("DISCORD_CLIENT_ID", "")
	c.Discord.ClientSecret = env("DISCORD_CLIENT_SECRET", "")
	c.Discord.CallbackURL = env("DISCORD_CALLBACK_URL", strings.TrimSuffix(c.PublicBaseURL, "/")+"/callback/discord")
	c.Discord.BotToken = env("DISCORD_BOT_TOKEN", "")
	c.Discord.PublicKey = env("DISCORD_PUBLIC_KEY", "")

	c.Google.BaseURL = env("GOOGLE_BASE_URL", "https://accounts.google.com")
	c.Google.ClientID = env("GOOGLE_CLIENT_ID", "")
	c.Google.ClientSecret = env("GOOGLE_CLIENT_SECRET", "")
	c.Google.CallbackURL = env("GOOGLE_CALLBACK_URL", strings.TrimSuffix(c.PublicBaseURL, "/")+"/callback/google")
	c.Google.AllowedDomains = envList("ALLOWED_DOMAINS")

	c.AddRoles = envList("ADD_ROLES")
	c.RemoveRoles = envList("REMOVE_ROLES")
	c.UnverifiedRoles = envList("UNVERIFIED_ROLES")

	c.AdminRoleIDs = envList("ADMIN_ROLE_IDS")
	c.AdminUserIDs = envList("ADMIN_USER_IDS")

	c.StateSecretName = env("STATE_SECRET_NAME", "discord-google-sso-state")
	c.Namespace = env("NAMESPACE", "")

	var err error
	if c.ReconcileInterval, err = envDur("RECONCILE_INTERVAL", 5*time.Minute); err != nil {
		return nil, err
	}
	if c.SessionTTL, err = envDur("SESSION_TTL", 10*time.Minute); err != nil {
		return nil, err
	}
	if c.ClockLeeway, err = envDur("CLOCK_LEEWAY", 30*time.Second); err != nil {
		return nil, err
	}
	// Namespace stays empty when unset: the single "unset" sentinel. The
	// server fills it from the Kubernetes client's namespace resolution
	// (in-cluster service account, else kubeconfig context) only when empty;
	// an explicitly configured value always wins.
	return c, c.Validate()
}

// Validate enforces required fields, formats, and the role-policy
// well-formedness rule: a role granted on verification must not appear in the
// removal-on-verification set or the initial/unverified set. This
// disjointness makes every operation's additions and removals
// order-independent, which is what makes grants and revocations idempotent.
func (c *Config) Validate() error {
	if c.GuildID == "" || !isNumeric(c.GuildID) {
		return fmt.Errorf("DGS_GUILD_ID must be set to the Discord guild (server) ID")
	}
	if err := validateBaseURL(c.PublicBaseURL, "DGS_PUBLIC_BASE_URL"); err != nil {
		return err
	}
	if c.Discord.ClientID == "" || c.Discord.ClientSecret == "" {
		return fmt.Errorf("DGS_DISCORD_CLIENT_ID and DGS_DISCORD_CLIENT_SECRET are required")
	}
	if c.Discord.BotToken == "" {
		return fmt.Errorf("DGS_DISCORD_BOT_TOKEN is required")
	}
	if err := validateHexKey(c.Discord.PublicKey); err != nil {
		return fmt.Errorf("DGS_DISCORD_PUBLIC_KEY: %w", err)
	}
	if err := validateBaseURL(c.Discord.BaseURL, "DGS_DISCORD_BASE_URL"); err != nil {
		return err
	}
	if err := validateURL(c.Discord.CallbackURL, "DGS_DISCORD_CALLBACK_URL"); err != nil {
		return err
	}
	if c.Google.ClientID == "" || c.Google.ClientSecret == "" {
		return fmt.Errorf("DGS_GOOGLE_CLIENT_ID and DGS_GOOGLE_CLIENT_SECRET are required")
	}
	if err := validateBaseURL(c.Google.BaseURL, "DGS_GOOGLE_BASE_URL"); err != nil {
		return err
	}
	if err := validateURL(c.Google.CallbackURL, "DGS_GOOGLE_CALLBACK_URL"); err != nil {
		return err
	}
	if len(c.Google.AllowedDomains) == 0 {
		return fmt.Errorf("DGS_ALLOWED_DOMAINS must list at least one Workspace domain")
	}
	for _, d := range c.Google.AllowedDomains {
		if d == "" || strings.Contains(d, " ") {
			return fmt.Errorf("DGS_ALLOWED_DOMAINS contains invalid domain %q", d)
		}
	}
	for _, r := range slices.Concat(c.AddRoles, c.RemoveRoles, c.UnverifiedRoles) {
		if !isNumeric(r) {
			return fmt.Errorf("role IDs must be numeric, got %q", r)
		}
	}
	if len(c.AdminRoleIDs) == 0 && len(c.AdminUserIDs) == 0 {
		return fmt.Errorf("DGS_ADMIN_ROLE_IDS or DGS_ADMIN_USER_IDS must be configured for /revoke authorization")
	}
	if c.StateSecretName == "" {
		return fmt.Errorf("DGS_STATE_SECRET_NAME must not be empty")
	}

	// Role-policy well-formedness.
	for _, granted := range c.AddRoles {
		for _, removed := range c.RemoveRoles {
			if granted == removed {
				return fmt.Errorf("role-policy misconfiguration: role %s is both granted and removed on verification", granted)
			}
		}
		for _, initial := range c.UnverifiedRoles {
			if granted == initial {
				return fmt.Errorf("role-policy misconfiguration: role %s is both granted on verification and in the initial/unverified set", granted)
			}
		}
	}
	if c.ReconcileInterval <= 0 || c.SessionTTL <= 0 {
		return fmt.Errorf("DGS_RECONCILE_INTERVAL and DGS_SESSION_TTL must be positive")
	}
	return nil
}

func validateBaseURL(raw, name string) error {
	u, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("%s: %w", name, err)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return fmt.Errorf("%s: scheme must be http or https", name)
	}
	if u.Host == "" {
		return fmt.Errorf("%s: host is required", name)
	}
	if strings.Contains(raw, "?") || strings.TrimSuffix(u.Path, "/") != "" {
		return fmt.Errorf("%s: must be a bare base URL without path or query", name)
	}
	return nil
}

func validateURL(raw, name string) error {
	if raw == "" {
		return fmt.Errorf("%s: required", name)
	}
	u, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("%s: %w", name, err)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return fmt.Errorf("%s: scheme must be http or https", name)
	}
	if u.Host == "" {
		return fmt.Errorf("%s: host is required", name)
	}
	return nil
}

func validateHexKey(hexKey string) error {
	if hexKey == "" {
		return fmt.Errorf("required (Discord application public key)")
	}
	b, err := hex.DecodeString(hexKey)
	if err != nil {
		return fmt.Errorf("must be hex-encoded: %w", err)
	}
	if len(b) != 32 {
		return fmt.Errorf("must be 32 bytes (64 hex chars), got %d bytes", len(b))
	}
	return nil
}

func isNumeric(s string) bool {
	if s == "" {
		return false
	}
	_, err := strconv.ParseUint(s, 10, 64)
	return err == nil
}
