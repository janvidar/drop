package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// base returns a minimal valid configuration, which each test then breaks in
// exactly one way.
func base() Config {
	c := Default()
	c.Server.Name = "drop.example.org"
	c.Server.AbuseContact = "abuse@example.org"
	c.Control.Hostnames = []string{"drop.example.org"}
	c.STUN = map[string]Family{
		"ipv4": {
			PrimaryBind:      "198.51.100.10",
			PrimaryAdvertise: "198.51.100.10",
			PrimaryPort:      3478,
		},
	}
	return c
}

func TestValidateAcceptsMinimal(t *testing.T) {
	if err := base().Validate(); err != nil {
		t.Fatalf("minimal config rejected: %v", err)
	}
}

func TestValidateAcceptsFullBehaviourDiscovery(t *testing.T) {
	c := base()
	c.STUN["ipv4"] = Family{
		PrimaryBind:        "198.51.100.10",
		PrimaryAdvertise:   "198.51.100.10",
		PrimaryPort:        3478,
		AlternateBind:      "198.51.100.11",
		AlternateAdvertise: "198.51.100.11",
		AlternatePort:      3479,
	}
	c.STUN["ipv6"] = Family{
		PrimaryBind:        "2001:db8:1::10",
		PrimaryAdvertise:   "2001:db8:1::10",
		PrimaryPort:        3478,
		AlternateBind:      "2001:db8:1::11",
		AlternateAdvertise: "2001:db8:1::11",
		AlternatePort:      3479,
	}
	if err := c.Validate(); err != nil {
		t.Fatalf("full config rejected: %v", err)
	}
	if !c.STUN["ipv4"].HasAlternate() || !c.STUN["ipv6"].HasAlternate() {
		t.Error("HasAlternate should be true for both families")
	}
}

// The DigitalOcean shape: the alternate address is delivered by DNAT to an
// anchor, so bind is a private address while advertise is the public reserved
// IP. This must be accepted -- it is the whole reason the two are separate.
func TestValidateAcceptsPrivateBindWithPublicAdvertise(t *testing.T) {
	c := base()
	c.STUN["ipv4"] = Family{
		PrimaryBind:        "201.79.4.56",
		PrimaryAdvertise:   "201.79.4.56",
		PrimaryPort:        3478,
		AlternateBind:      "10.19.0.6", // anchor address, never public
		AlternateAdvertise: "203.0.113.9",
		AlternatePort:      3479,
	}
	if err := c.Validate(); err != nil {
		t.Fatalf("anchor-style config rejected: %v", err)
	}
}

func TestValidateRejects(t *testing.T) {
	cases := []struct {
		name    string
		mutate  func(*Config)
		wantSub string
	}{
		{
			"no server name",
			func(c *Config) { c.Server.Name = "" },
			"server.name",
		},
		{
			"no abuse contact",
			func(c *Config) { c.Server.AbuseContact = "" },
			"abuse_contact",
		},
		{
			"no hostnames",
			func(c *Config) { c.Control.Hostnames = nil },
			"control.hostnames",
		},
		{
			"cert without key",
			func(c *Config) { c.Control.TLSCert = "/x.pem" },
			"must be set together",
		},
		{
			"no stun families",
			func(c *Config) { c.STUN = nil },
			"at least one",
		},
		{
			"unknown family name",
			func(c *Config) { c.STUN = map[string]Family{"ipv5": c.STUN["ipv4"]} },
			"unknown family",
		},
		{
			"v6 address in v4 section",
			func(c *Config) {
				f := c.STUN["ipv4"]
				f.PrimaryAdvertise = "2001:db8::1"
				c.STUN["ipv4"] = f
			},
			"IPv6 address in the ipv4 section",
		},
		{
			"unparseable address",
			func(c *Config) {
				f := c.STUN["ipv4"]
				f.PrimaryBind = "not-an-ip"
				c.STUN["ipv4"] = f
			},
			"is not an IP address",
		},
		{
			// The mistake that produces a server which works locally and
			// publishes an unreachable OTHER-ADDRESS in production.
			"private advertised address",
			func(c *Config) {
				f := c.STUN["ipv4"]
				f.PrimaryAdvertise = "10.19.0.6"
				c.STUN["ipv4"] = f
			},
			"not publicly routable",
		},
		{
			"cgnat advertised address",
			func(c *Config) {
				f := c.STUN["ipv4"]
				f.PrimaryAdvertise = "100.64.1.1"
				c.STUN["ipv4"] = f
			},
			"not publicly routable",
		},
		{
			"partial alternate configuration",
			func(c *Config) {
				f := c.STUN["ipv4"]
				f.AlternateBind = "198.51.100.11"
				c.STUN["ipv4"] = f
			},
			"must all be set, or all be empty",
		},
		{
			// Behaviour discovery against one address silently reports
			// endpoint-independent mapping for everyone.
			"identical advertised addresses",
			func(c *Config) {
				f := c.STUN["ipv4"]
				f.AlternateBind = "198.51.100.11"
				f.AlternateAdvertise = "198.51.100.10"
				f.AlternatePort = 3479
				c.STUN["ipv4"] = f
			},
			"two distinct public addresses",
		},
		{
			"identical bind addresses",
			func(c *Config) {
				f := c.STUN["ipv4"]
				f.AlternateBind = "198.51.100.10"
				f.AlternateAdvertise = "198.51.100.11"
				f.AlternatePort = 3479
				c.STUN["ipv4"] = f
			},
			"share one socket address",
		},
		{
			"identical ports",
			func(c *Config) {
				f := c.STUN["ipv4"]
				f.AlternateBind = "198.51.100.11"
				f.AlternateAdvertise = "198.51.100.11"
				f.AlternatePort = 3478
				c.STUN["ipv4"] = f
			},
			"two distinct ports",
		},
		{
			"duplicate egress port",
			func(c *Config) { c.Egress.BannerPorts = []int{411, 411} },
			"already used by",
		},
		{
			"invalid egress port",
			func(c *Config) { c.Egress.BannerPorts = []int{0} },
			"not a valid port",
		},
		{
			"port cap too high",
			func(c *Config) { c.Limits.MaxPortsPerTest = 64 },
			"port scanner",
		},
		{
			"inbound deadline over spec cap",
			func(c *Config) { c.Limits.InboundDeadline = Duration{30e9} },
			"may not exceed 15s",
		},
		{
			"deadline shorter than probe timeout",
			func(c *Config) { c.Limits.InboundDeadline = Duration{1e9} },
			"at least limits.probe_timeout",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := base()
			tc.mutate(&c)
			err := c.Validate()
			if err == nil {
				t.Fatalf("expected rejection, got none")
			}
			if !strings.Contains(err.Error(), tc.wantSub) {
				t.Errorf("error %q does not mention %q", err, tc.wantSub)
			}
		})
	}
}

// Two families may reuse the same UDP port numbers, because they bind
// different addresses. Rejecting that would be wrong.
func TestValidateAllowsSamePortsAcrossFamilies(t *testing.T) {
	c := base()
	c.STUN["ipv6"] = Family{
		PrimaryBind:      "2001:db8::10",
		PrimaryAdvertise: "2001:db8::10",
		PrimaryPort:      3478,
	}
	if err := c.Validate(); err != nil {
		t.Fatalf("same port across families rejected: %v", err)
	}
}

func TestLoad(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "dropd.toml")
	content := `
[server]
name = "drop.example.org"
operator = "example.org"
abuse_contact = "abuse@example.org"

[control]
hostnames = ["drop.example.org", "v4.drop.example.org", "v6.drop.example.org"]

[limits]
probe_timeout = "3s"

[stun.ipv4]
primary_bind = "198.51.100.10"
primary_advertise = "198.51.100.10"
primary_port = 3478
`
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Server.Name != "drop.example.org" {
		t.Errorf("name = %q", cfg.Server.Name)
	}
	if len(cfg.Control.Hostnames) != 3 {
		t.Errorf("hostnames = %v", cfg.Control.Hostnames)
	}
	if cfg.Limits.ProbeTimeout.Duration.Seconds() != 3 {
		t.Errorf("probe_timeout = %v", cfg.Limits.ProbeTimeout)
	}
	// Defaults must survive a partial [limits] table.
	if cfg.Limits.MaxPortsPerTest != 4 {
		t.Errorf("max_ports_per_test = %d, want the default 4", cfg.Limits.MaxPortsPerTest)
	}
	if cfg.Control.HTTPSAddr != ":443" {
		t.Errorf("https_addr = %q, want the default", cfg.Control.HTTPSAddr)
	}
	if !cfg.Control.UsesACME() {
		t.Error("UsesACME should be true when no cert is configured")
	}
}

// A typo in a key that matters -- a rate limit, a port -- must not be ignored.
func TestLoadRejectsUnknownKeys(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "dropd.toml")
	content := `
[server]
name = "drop.example.org"
abuse_contact = "abuse@example.org"
[control]
hostnames = ["drop.example.org"]
[limits]
sessions_per_hourr = 999
[stun.ipv4]
primary_bind = "198.51.100.10"
primary_advertise = "198.51.100.10"
primary_port = 3478
`
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := Load(path)
	if err == nil {
		t.Fatal("expected rejection of unknown key")
	}
	if !strings.Contains(err.Error(), "unknown configuration keys") {
		t.Errorf("unexpected error: %v", err)
	}
}
