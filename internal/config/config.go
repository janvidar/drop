// Package config loads and validates the dropd configuration.
//
// Validation is the point of this package. A DROP server that starts with a
// subtly wrong address configuration does not fail visibly -- it answers every
// request, and quietly misclassifies every NAT behind it. So the rule here is
// that anything checkable at startup is checked at startup, and a
// misconfiguration is a refusal to start rather than a log line nobody reads.
package config

import (
	"errors"
	"fmt"
	"net/netip"
	"time"

	"github.com/BurntSushi/toml"

	"quickdc.org/drop/internal/ipclass"
)

// Config is the whole of dropd's configuration.
type Config struct {
	Server      Server            `toml:"server"`
	Control     Control           `toml:"control"`
	Limits      Limits            `toml:"limits"`
	STUN        map[string]Family `toml:"stun"`
	Egress      Egress            `toml:"egress"`
	Metrics     Metrics           `toml:"metrics"`
	State       State             `toml:"state"`
	Development Development       `toml:"development"`
}

// Development relaxes checks that would otherwise make local testing
// impossible. Every field here is named to be conspicuous in a config file and
// in a grep, because each one disables a check that exists for a reason.
type Development struct {
	// AllowUnroutableAdvertise permits loopback and private addresses in the
	// advertised fields, so that the whole daemon can be run on 127.0.0.0/8.
	//
	// In production this check is what catches the bind-versus-advertise
	// mistake -- publishing an interface address from behind NAT, which
	// produces a server that works locally and hands every client an
	// unreachable OTHER-ADDRESS.
	AllowUnroutableAdvertise bool `toml:"allow_unroutable_advertise"`
}

// Server is the service's public identity. The abuse contact is required, not
// optional: this daemon opens TCP connections to residential addresses, those
// generate complaints, and a complaint with nowhere to go becomes a suspended
// host.
type Server struct {
	Name         string `toml:"name"`
	Operator     string `toml:"operator"`
	AbuseContact string `toml:"abuse_contact"`
}

// Control is the HTTPS control plane.
type Control struct {
	// Hostnames autocert will obtain certificates for. The specification
	// requires three: a dual-stack name, a v4-only name and a v6-only name.
	Hostnames []string `toml:"hostnames"`

	HTTPSAddr string `toml:"https_addr"`
	HTTPAddr  string `toml:"http_addr"`

	ACMEDirectory string `toml:"acme_directory"` // empty means Let's Encrypt production
	ACMEEmail     string `toml:"acme_email"`

	// TLSCert and TLSKey bypass ACME entirely. Intended for local testing and
	// for operators who already manage certificates elsewhere.
	TLSCert string `toml:"tls_cert"`
	TLSKey  string `toml:"tls_key"`
}

// UsesACME reports whether the control plane should obtain its own certificate.
func (c Control) UsesACME() bool { return c.TLSCert == "" && c.TLSKey == "" }

// Limits are the spec's rate and size caps, all operator-tunable because the
// right values depend on how much abuse budget the operator has.
type Limits struct {
	MaxPortsPerTest int      `toml:"max_ports_per_test"`
	MinPort         int      `toml:"min_port"`
	ProbeTimeout    Duration `toml:"probe_timeout"`
	InboundDeadline Duration `toml:"inbound_deadline"`
	SessionTTL      Duration `toml:"session_ttl"`
	SessionsPerHour int      `toml:"sessions_per_hour"`
	MaxSessions     int      `toml:"max_sessions"`
}

// Family is one address family's STUN configuration.
//
// Bind and advertise are separate for a reason that only shows up in
// production. On DigitalOcean -- and on other providers with the same design
// -- a secondary address is delivered by translating it to a hidden per-host
// anchor address. The machine never sees the real address on any interface, so
// a socket must bind the anchor while OTHER-ADDRESS must carry the public
// address. Deriving one from the other produces a server that passes every
// local test and publishes an unreachable OTHER-ADDRESS in production.
type Family struct {
	PrimaryBind      string `toml:"primary_bind"`
	PrimaryAdvertise string `toml:"primary_advertise"`
	PrimaryPort      int    `toml:"primary_port"`

	// The alternate pair is optional. Without it, RFC 5780 behaviour discovery
	// is impossible and this family simply does not advertise "nat".
	AlternateBind      string `toml:"alternate_bind"`
	AlternateAdvertise string `toml:"alternate_advertise"`
	AlternatePort      int    `toml:"alternate_port"`
}

// HasAlternate reports whether this family can do behaviour discovery.
func (f Family) HasAlternate() bool {
	return f.AlternateBind != "" && f.AlternateAdvertise != "" && f.AlternatePort != 0
}

// Egress lists the ports used for the outbound-reachability test.
type Egress struct {
	// BannerPorts speak first with "DROP/1 EGRESS <port>".
	BannerPorts []int `toml:"banner_ports"`
}

// Metrics is the Prometheus endpoint. It defaults to loopback and should stay
// there: it is unauthenticated.
type Metrics struct {
	Addr string `toml:"addr"`
}

// State is where mutable data lives -- the ACME cache and the server secret.
type State struct {
	Dir string `toml:"dir"`
}

// Duration is a time.Duration that decodes from a TOML string like "5s".
type Duration struct{ time.Duration }

func (d *Duration) UnmarshalText(text []byte) error {
	v, err := time.ParseDuration(string(text))
	if err != nil {
		return err
	}
	d.Duration = v
	return nil
}

func (d Duration) MarshalText() ([]byte, error) { return []byte(d.String()), nil }

// Default returns a configuration with every optional value populated. Load
// starts from this, so an operator only writes what differs.
func Default() Config {
	return Config{
		Control: Control{
			HTTPSAddr: ":443",
			HTTPAddr:  ":80",
		},
		Limits: Limits{
			MaxPortsPerTest: 4,
			MinPort:         1024,
			ProbeTimeout:    Duration{5 * time.Second},
			InboundDeadline: Duration{15 * time.Second},
			SessionTTL:      Duration{60 * time.Second},
			SessionsPerHour: 12,
			MaxSessions:     4096,
		},
		Egress: Egress{
			BannerPorts: []int{411, 412, 1511, 5000},
		},
		Metrics: Metrics{Addr: "127.0.0.1:9779"},
		State:   State{Dir: "/var/lib/dropd"},
	}
}

// Load reads path, applies it over Default, and validates the result.
func Load(path string) (Config, error) {
	cfg := Default()
	md, err := toml.DecodeFile(path, &cfg)
	if err != nil {
		return Config{}, fmt.Errorf("reading %s: %w", path, err)
	}
	// An unrecognised key is almost always a typo in a key that matters, and
	// silently ignoring it is how a rate limit ends up not applied.
	if undecoded := md.Undecoded(); len(undecoded) > 0 {
		return Config{}, fmt.Errorf("%s: unknown configuration keys: %v", path, undecoded)
	}
	if err := cfg.Validate(); err != nil {
		return Config{}, fmt.Errorf("%s: %w", path, err)
	}
	return cfg, nil
}

// Validate reports the first fatal problem with the configuration.
func (c Config) Validate() error {
	if c.Server.Name == "" {
		return errors.New("server.name is required")
	}
	if c.Server.AbuseContact == "" {
		return errors.New("server.abuse_contact is required: this daemon " +
			"connects out to residential addresses and will attract complaints")
	}
	if len(c.Control.Hostnames) == 0 {
		return errors.New("control.hostnames is required")
	}
	if (c.Control.TLSCert == "") != (c.Control.TLSKey == "") {
		return errors.New("control.tls_cert and control.tls_key must be set together")
	}
	if c.State.Dir == "" {
		return errors.New("state.dir is required")
	}

	if err := c.Limits.validate(); err != nil {
		return err
	}
	if len(c.STUN) == 0 {
		return errors.New("at least one [stun.ipv4] or [stun.ipv6] section is required")
	}

	// Ports are tracked per protocol: a UDP 3478 and a TCP 3478 do not
	// collide, but two UDP 3478s do.
	used := portClaims{}
	for _, p := range c.Egress.BannerPorts {
		if p < 1 || p > 65535 {
			return fmt.Errorf("egress.banner_ports: %d is not a valid port", p)
		}
		if err := used.claimTCP(p, "egress.banner_ports"); err != nil {
			return err
		}
	}

	for name, f := range c.STUN {
		want, err := familyOf(name)
		if err != nil {
			return err
		}
		if err := f.validate(name, want, used, c.Development.AllowUnroutableAdvertise); err != nil {
			return err
		}
	}
	return nil
}

func (l Limits) validate() error {
	if l.MaxPortsPerTest < 1 {
		return errors.New("limits.max_ports_per_test must be at least 1")
	}
	if l.MaxPortsPerTest > 16 {
		return errors.New("limits.max_ports_per_test above 16 turns the " +
			"service into a port scanner for shared CGNAT addresses")
	}
	if l.MinPort < 1 || l.MinPort > 65535 {
		return errors.New("limits.min_port must be between 1 and 65535")
	}
	if l.ProbeTimeout.Duration <= 0 {
		return errors.New("limits.probe_timeout must be positive")
	}
	if l.InboundDeadline.Duration < l.ProbeTimeout.Duration {
		return errors.New("limits.inbound_deadline must be at least limits.probe_timeout")
	}
	if l.InboundDeadline.Duration > 15*time.Second {
		return errors.New("limits.inbound_deadline may not exceed 15s (specification)")
	}
	if l.SessionTTL.Duration <= 0 {
		return errors.New("limits.session_ttl must be positive")
	}
	if l.SessionsPerHour < 1 {
		return errors.New("limits.sessions_per_hour must be at least 1")
	}
	if l.MaxSessions < 1 {
		return errors.New("limits.max_sessions must be at least 1")
	}
	return nil
}

func familyOf(name string) (bool /*wantV4*/, error) {
	switch name {
	case "ipv4":
		return true, nil
	case "ipv6":
		return false, nil
	default:
		return false, fmt.Errorf("stun.%s: unknown family, expected ipv4 or ipv6", name)
	}
}

func (f Family) validate(name string, wantV4 bool, used portClaims, allowUnroutable bool) error {
	if f.PrimaryBind == "" || f.PrimaryAdvertise == "" {
		return fmt.Errorf("stun.%s: primary_bind and primary_advertise are required", name)
	}
	if f.PrimaryPort < 1 || f.PrimaryPort > 65535 {
		return fmt.Errorf("stun.%s: primary_port is required and must be a valid port", name)
	}

	primaryBind, err := parseFamilyAddr(name, "primary_bind", f.PrimaryBind, wantV4)
	if err != nil {
		return err
	}
	primaryAdv, err := parseAdvertised(name, "primary_advertise", f.PrimaryAdvertise, wantV4, allowUnroutable)
	if err != nil {
		return err
	}

	if !f.HasAlternate() {
		// Partial configuration is a mistake worth catching: the operator
		// meant to enable behaviour discovery and left something out.
		if f.AlternateBind != "" || f.AlternateAdvertise != "" || f.AlternatePort != 0 {
			return fmt.Errorf("stun.%s: alternate_bind, alternate_advertise and "+
				"alternate_port must all be set, or all be empty", name)
		}
		return used.claimUDP(primaryBind, f.PrimaryPort, "stun."+name)
	}

	alternateBind, err := parseFamilyAddr(name, "alternate_bind", f.AlternateBind, wantV4)
	if err != nil {
		return err
	}
	alternateAdv, err := parseAdvertised(name, "alternate_advertise", f.AlternateAdvertise, wantV4, allowUnroutable)
	if err != nil {
		return err
	}
	if f.AlternatePort < 1 || f.AlternatePort > 65535 {
		return fmt.Errorf("stun.%s: alternate_port must be a valid port", name)
	}

	// RFC 5780 distinguishes mapping behaviour by observing responses from a
	// genuinely different address and a genuinely different port. If either
	// pair collapses, every client still gets an answer -- a confident, wrong
	// one -- so these are refusals to start rather than warnings.
	if primaryAdv == alternateAdv {
		return fmt.Errorf("stun.%s: primary_advertise and alternate_advertise are "+
			"both %s; behaviour discovery needs two distinct public addresses",
			name, primaryAdv)
	}
	if primaryBind == alternateBind {
		return fmt.Errorf("stun.%s: primary_bind and alternate_bind are both %s; "+
			"the two endpoints would share one socket address", name, primaryBind)
	}
	if f.PrimaryPort == f.AlternatePort {
		return fmt.Errorf("stun.%s: primary_port and alternate_port are both %d; "+
			"behaviour discovery needs two distinct ports", name, f.PrimaryPort)
	}

	// RFC 5780 needs all four (address, port) combinations to be bindable, so
	// both ports are claimed against both bind addresses.
	for _, bind := range []netip.Addr{primaryBind, alternateBind} {
		for _, port := range []int{f.PrimaryPort, f.AlternatePort} {
			if err := used.claimUDP(bind, port, "stun."+name); err != nil {
				return err
			}
		}
	}
	return nil
}

// portClaims records which config section claimed which socket address, so a
// duplicate is reported against the section it collides with.
//
// Claims are keyed by bind address as well as port, because that is what the
// kernel actually arbitrates: IPv4 and IPv6 both using 3478 is the normal
// configuration, not a conflict, and so is the same port on two different
// addresses of one family.
type portClaims map[string]string

func (pc portClaims) claimUDP(bind netip.Addr, port int, owner string) error {
	return pc.claim("udp", netip.AddrPortFrom(bind, uint16(port)).String(), port, owner)
}

// claimTCP claims a port across every address, for listeners that bind
// wildcard rather than a specific address.
func (pc portClaims) claimTCP(port int, owner string) error {
	return pc.claim("tcp", fmt.Sprintf("*:%d", port), port, owner)
}

func (pc portClaims) claim(proto, key string, port int, owner string) error {
	key = proto + "/" + key
	if prev, dup := pc[key]; dup {
		return fmt.Errorf("%s: %s port %d is already used by %s", owner, proto, port, prev)
	}
	pc[key] = owner
	return nil
}

func parseFamilyAddr(section, field, value string, wantV4 bool) (netip.Addr, error) {
	addr, err := netip.ParseAddr(value)
	if err != nil {
		return netip.Addr{}, fmt.Errorf("stun.%s: %s: %q is not an IP address",
			section, field, value)
	}
	addr = addr.Unmap()
	if addr.Is4() != wantV4 {
		return netip.Addr{}, fmt.Errorf("stun.%s: %s: %s is an %s address in the %s section",
			section, field, value, familyName(addr.Is4()), section)
	}
	return addr, nil
}

// parseAdvertised additionally requires the address to be publicly routable.
// Advertised addresses are what clients are told to send traffic to; a private
// one there means the operator published an interface address from behind NAT,
// which is exactly the bind-versus-advertise mistake this config shape exists
// to prevent.
func parseAdvertised(section, field, value string, wantV4, allowUnroutable bool) (netip.Addr, error) {
	addr, err := parseFamilyAddr(section, field, value, wantV4)
	if err != nil {
		return netip.Addr{}, err
	}
	if allowUnroutable {
		return addr, nil
	}
	if class := ipclass.Of(addr); !class.Routable() {
		return netip.Addr{}, fmt.Errorf("stun.%s: %s: %s classifies as %q and is "+
			"not publicly routable", section, field, addr, class)
	}
	return addr, nil
}

func familyName(is4 bool) string {
	if is4 {
		return "IPv4"
	}
	return "IPv6"
}
