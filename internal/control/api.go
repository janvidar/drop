// Package control implements the DROP HTTPS control plane.
package control

import "time"

// Protocol is the value of the "protocol" member, and the version marker
// clients use to confirm they reached a DROP server rather than a captive
// portal.
const Protocol = "DROP/1"

// ServerDoc is the body of GET /v1/server.
type ServerDoc struct {
	Protocol     string `json:"protocol"`
	Server       string `json:"server"`
	Operator     string `json:"operator,omitempty"`
	AbuseContact string `json:"abuse_contact"`

	// Tests is keyed by address family ("ipv4", "ipv6"). The two lists
	// routinely differ, because a second IPv6 address is normally free while a
	// second IPv4 address is not. Clients must not infer one from the other.
	Tests map[string][]string `json:"tests"`

	STUN   *STUNDoc  `json:"stun,omitempty"`
	Egress EgressDoc `json:"egress"`
	Limits LimitsDoc `json:"limits"`
}

// STUNDoc advertises the endpoints used for the UDP tests. Addresses here are
// always the advertised ones, never the bound ones.
type STUNDoc struct {
	Primary   *STUNEndpoint `json:"primary,omitempty"`
	Alternate *STUNEndpoint `json:"alternate,omitempty"`
}

// STUNEndpoint is one endpoint per family at a shared port.
type STUNEndpoint struct {
	IPv4 string `json:"ipv4,omitempty"`
	IPv6 string `json:"ipv6,omitempty"`
	Port int    `json:"port"`
}

// EgressDoc lists the ports for the outbound-reachability test, split by how
// the client must confirm it truly reached us. A bare connect proves nothing:
// a transparent proxy or captive portal will accept it happily.
type EgressDoc struct {
	IPv4 string `json:"ipv4,omitempty"`
	IPv6 string `json:"ipv6,omitempty"`

	// BannerPorts speak first with "DROP/1 EGRESS <port>".
	BannerPorts []int `json:"banner_ports"`
	// HTTPPorts and HTTPSPorts carry the control plane and cannot speak
	// first; the test there is a successful /v1/server fetch.
	HTTPPorts  []int `json:"http_ports,omitempty"`
	HTTPSPorts []int `json:"https_ports,omitempty"`
}

// LimitsDoc tells clients the caps before they hit them.
type LimitsDoc struct {
	MaxPortsPerTest   int `json:"max_ports_per_test"`
	MinPort           int `json:"min_port"`
	SessionsPerHour   int `json:"sessions_per_hour"`
	ProbeTimeoutMS    int `json:"probe_timeout_ms"`
	InboundDeadlineMS int `json:"inbound_deadline_ms"`
}

// WhoamiDoc is the body of GET /v1/whoami.
type WhoamiDoc struct {
	IP     string `json:"ip"`
	Family string `json:"family"`
	// Port is the observed source port. Compared with the client's own local
	// port it reveals TCP source-port rewriting before any probe runs.
	Port           int    `json:"port"`
	Classification string `json:"classification"`
	// Advice is a plain-language explanation of the classification. It lives
	// here so that every client shows the user the same explanation instead of
	// inventing its own.
	Advice     string    `json:"advice,omitempty"`
	ObservedAt time.Time `json:"observed_at"`
}

// ErrorDoc is the body of every non-2xx response.
type ErrorDoc struct {
	Error  string `json:"error"`
	Detail string `json:"detail,omitempty"`
}

// requestBodyTypes lists every type decoded from a client request body.
//
// Any new request type MUST be registered here. The registry exists so that
// TestNoRequestTypeCanCarryATargetAddress can walk these types and fail the
// build if one grows a field that could name an address. The source-address
// rule -- the server probes the source of the control connection and nothing
// else -- is what keeps this service from being an aimable port scanner, and a
// rule enforced only by review is a rule that eventually breaks.
func requestBodyTypes() []any {
	return []any{}
}

// Error codes. These are part of the wire contract: clients switch on them.
const (
	ErrMalformed      = "malformed_request"
	ErrWrongSource    = "wrong_source_address"
	ErrUnknownSession = "unknown_session"
	ErrAlreadyRan     = "session_already_ran"
	ErrTooLarge       = "request_too_large"
	ErrPortRange      = "port_out_of_range"
	ErrTooManyPorts   = "too_many_ports"
	ErrRateLimited    = "rate_limited"
	ErrUnavailable    = "unavailable"
	ErrNotFound       = "not_found"
	ErrMethod         = "method_not_allowed"
)
