// Package dropclient is a reference implementation of the DROP client flow.
//
// It exists to be read as much as to be run. A DC client author should be able
// to follow this file top to bottom and see the whole protocol: learn your
// address, open a session, arm your listeners, ask for the probes, then apply
// the decision table. The interesting parts are the ones that are easy to get
// wrong -- binding the control socket deliberately, running the STUN agent on
// the socket you actually advertise, and refusing to answer probes that do not
// authenticate.
package dropclient

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"time"

	"quickdc.org/drop/internal/natdisc"
	"quickdc.org/drop/internal/stun"
)

// Family selects which address family a run tests. One TCP connection has one
// source address, so a client that wants both must run the flow twice.
type Family string

const (
	IPv4 Family = "ipv4"
	IPv6 Family = "ipv6"
)

// Client talks to one DROP server.
type Client struct {
	// BaseURL is the family-specific endpoint, e.g.
	// https://v4.drop.example.org. Using the family-specific name rather than
	// relying on Happy Eyeballs is what makes the family under test
	// deterministic.
	BaseURL string
	Family  Family

	// LocalAddr pins the source address of the control connection.
	//
	// This is the client's only lever over what gets tested, and on IPv6 it is
	// essential: a client listening on [::] does not choose its own source
	// address, and with privacy extensions the kernel will pick a temporary
	// one. DROP would then faithfully validate an address the client never
	// advertises, or one that expires underneath the advertisement.
	LocalAddr netip.Addr

	UserAgent string
	Timeout   time.Duration

	http *http.Client
	// controlPort records the local port of the last control connection, so
	// the server can be told and can detect source-port rewriting.
	controlPort int
}

// New returns a client with sensible defaults.
func New(baseURL string, family Family, localAddr netip.Addr) *Client {
	c := &Client{
		BaseURL:   strings.TrimRight(baseURL, "/"),
		Family:    family,
		LocalAddr: localAddr,
		UserAgent: "dropcheck/1.0",
		Timeout:   30 * time.Second,
	}

	network := "tcp4"
	if family == IPv6 {
		network = "tcp6"
	}
	dialer := &net.Dialer{Timeout: 10 * time.Second}
	if localAddr.IsValid() {
		dialer.LocalAddr = &net.TCPAddr{IP: localAddr.AsSlice()}
	}

	c.http = &http.Client{
		Timeout: c.Timeout,
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, _, addr string) (net.Conn, error) {
				conn, err := dialer.DialContext(ctx, network, addr)
				if err != nil {
					return nil, err
				}
				// Remember our own source port so the server can compare it
				// with what it observed.
				if ap, err := netip.ParseAddrPort(conn.LocalAddr().String()); err == nil {
					c.controlPort = int(ap.Port())
				}
				return conn, nil
			},
			ForceAttemptHTTP2:   true,
			MaxIdleConnsPerHost: 2,
		},
	}
	return c
}

// --- wire types -------------------------------------------------------------

type ServerDoc struct {
	Protocol     string              `json:"protocol"`
	Server       string              `json:"server"`
	Operator     string              `json:"operator"`
	AbuseContact string              `json:"abuse_contact"`
	Tests        map[string][]string `json:"tests"`
	STUN         *STUNDoc            `json:"stun"`
	Egress       EgressDoc           `json:"egress"`
	Limits       LimitsDoc           `json:"limits"`
}

type STUNDoc struct {
	Primary   *STUNEndpoint `json:"primary"`
	Alternate *STUNEndpoint `json:"alternate"`
}

type STUNEndpoint struct {
	IPv4 string `json:"ipv4"`
	IPv6 string `json:"ipv6"`
	Port int    `json:"port"`
}

// AddrPort returns the endpoint for a family.
func (e *STUNEndpoint) AddrPort(f Family) (netip.AddrPort, bool) {
	if e == nil {
		return netip.AddrPort{}, false
	}
	s := e.IPv4
	if f == IPv6 {
		s = e.IPv6
	}
	addr, err := netip.ParseAddr(s)
	if err != nil {
		return netip.AddrPort{}, false
	}
	return netip.AddrPortFrom(addr, uint16(e.Port)), true
}

type EgressDoc struct {
	IPv4        string `json:"ipv4"`
	IPv6        string `json:"ipv6"`
	BannerPorts []int  `json:"banner_ports"`
	HTTPPorts   []int  `json:"http_ports"`
	HTTPSPorts  []int  `json:"https_ports"`
}

type LimitsDoc struct {
	MaxPortsPerTest   int `json:"max_ports_per_test"`
	MinPort           int `json:"min_port"`
	SessionsPerHour   int `json:"sessions_per_hour"`
	ProbeTimeoutMS    int `json:"probe_timeout_ms"`
	InboundDeadlineMS int `json:"inbound_deadline_ms"`
}

type WhoamiDoc struct {
	IP             string    `json:"ip"`
	Family         string    `json:"family"`
	Port           int       `json:"port"`
	Classification string    `json:"classification"`
	Advice         string    `json:"advice"`
	ObservedAt     time.Time `json:"observed_at"`
}

type SessionDoc struct {
	SessionID string      `json:"session_id"`
	ExpiresIn int         `json:"expires_in"`
	Observed  ObservedDoc `json:"observed"`
	STUN      *STUNDoc    `json:"stun"`
	Creds     *Creds      `json:"credentials"`
	Limits    LimitsDoc   `json:"limits"`
}

type ObservedDoc struct {
	IP             string `json:"ip"`
	Family         string `json:"family"`
	Port           int    `json:"port"`
	Classification string `json:"classification"`
}

type Creds struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type PortResult struct {
	Port          int    `json:"port"`
	Verdict       string `json:"verdict"`
	RTTMS         int    `json:"rtt_ms"`
	RespondedFrom string `json:"responded_from"`
	Detail        string `json:"detail"`
}

type InboundDoc struct {
	SessionID string       `json:"session_id"`
	Observed  ObservedDoc  `json:"observed"`
	TCP       []PortResult `json:"tcp"`
	UDP       []PortResult `json:"udp"`
	Notes     []string     `json:"notes"`
	ElapsedMS int          `json:"elapsed_ms"`
}

// APIError is a non-2xx response.
type APIError struct {
	Status int
	Code   string `json:"error"`
	Detail string `json:"detail"`
}

func (e *APIError) Error() string {
	if e.Detail != "" {
		return fmt.Sprintf("drop: %d %s: %s", e.Status, e.Code, e.Detail)
	}
	return fmt.Sprintf("drop: %d %s", e.Status, e.Code)
}

// --- control plane ----------------------------------------------------------

// Server fetches the capability document.
func (c *Client) Server(ctx context.Context) (*ServerDoc, error) {
	var doc ServerDoc
	if err := c.do(ctx, "GET", "/v1/server", nil, &doc); err != nil {
		return nil, err
	}
	// Confirm we reached a DROP server rather than a captive portal that
	// happily returns 200 for everything.
	if doc.Protocol != "DROP/1" {
		return nil, fmt.Errorf("drop: unexpected protocol %q; this may not be a DROP server", doc.Protocol)
	}
	return &doc, nil
}

// Whoami fetches the reflexive address. It costs nothing and needs no session,
// so a client that only wants its public address can stop here.
func (c *Client) Whoami(ctx context.Context) (*WhoamiDoc, error) {
	var doc WhoamiDoc
	if err := c.do(ctx, "GET", "/v1/whoami", nil, &doc); err != nil {
		return nil, err
	}
	return &doc, nil
}

// OpenSession requests an authorisation to be probed.
func (c *Client) OpenSession(ctx context.Context, tests []string) (*SessionDoc, error) {
	req := map[string]any{"version": 1, "client": c.UserAgent}
	if len(tests) > 0 {
		req["tests"] = tests
	}
	var doc SessionDoc
	if err := c.do(ctx, "POST", "/v1/session", req, &doc); err != nil {
		return nil, err
	}
	return &doc, nil
}

// Inbound asks the server to probe the given ports.
func (c *Client) Inbound(ctx context.Context, sessionID string, tcpPorts, udpPorts []int) (*InboundDoc, error) {
	req := map[string]any{}
	if len(tcpPorts) > 0 {
		req["tcp"] = tcpPorts
	}
	if len(udpPorts) > 0 {
		req["udp"] = udpPorts
	}
	if c.controlPort != 0 {
		req["control_port"] = c.controlPort
	}
	var doc InboundDoc
	if err := c.do(ctx, "POST", "/v1/session/"+sessionID+"/inbound", req, &doc); err != nil {
		return nil, err
	}
	return &doc, nil
}

func (c *Client) do(ctx context.Context, method, path string, body, out any) error {
	var rdr io.Reader
	if body != nil {
		buf, err := json.Marshal(body)
		if err != nil {
			return err
		}
		rdr = bytes.NewReader(buf)
	}

	req, err := http.NewRequestWithContext(ctx, method, c.BaseURL+path, rdr)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", c.UserAgent)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	resp, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	// Bounded: a hostile or broken server must not be able to make the client
	// buffer without limit.
	data, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return err
	}

	if resp.StatusCode/100 != 2 {
		apiErr := &APIError{Status: resp.StatusCode}
		_ = json.Unmarshal(data, apiErr)
		if apiErr.Code == "" {
			apiErr.Code = strings.ToLower(strings.ReplaceAll(http.StatusText(resp.StatusCode), " ", "_"))
		}
		return apiErr
	}
	if out == nil {
		return nil
	}
	return json.Unmarshal(data, out)
}

// --- responders -------------------------------------------------------------

// TCPResponder answers DROP challenges on a client's listening port.
//
// A real DC client would fold this into its existing client-to-client
// listener, demultiplexing on the first bytes: "CSUP" for ADC, 0x16 0x03 for
// TLS, and "DROP/1 " for a challenge. A TLS-only port must still accept the
// plaintext challenge, since recognising a seven-byte prefix before the
// handshake is trivial and requiring TLS for a single-use nonce buys nothing.
type TCPResponder struct {
	ln net.Listener
}

// ListenTCP starts a responder on the given address.
func ListenTCP(network, address string) (*TCPResponder, error) {
	ln, err := net.Listen(network, address)
	if err != nil {
		return nil, err
	}
	r := &TCPResponder{ln: ln}
	go r.serve()
	return r, nil
}

// Port reports the bound port.
func (r *TCPResponder) Port() int {
	ap, err := netip.ParseAddrPort(r.ln.Addr().String())
	if err != nil {
		return 0
	}
	return int(ap.Port())
}

// Close stops the responder.
func (r *TCPResponder) Close() error { return r.ln.Close() }

func (r *TCPResponder) serve() {
	for {
		conn, err := r.ln.Accept()
		if err != nil {
			return
		}
		go func() {
			defer conn.Close()
			_ = conn.SetDeadline(time.Now().Add(10 * time.Second))

			// The line cap is part of the protocol: neither side may be made
			// to buffer by a hostile peer.
			buf := make([]byte, 128)
			n, err := conn.Read(buf)
			if err != nil {
				return
			}
			line := strings.TrimRight(string(buf[:n]), "\r\n")
			nonce, ok := strings.CutPrefix(line, "DROP/1 CHALLENGE ")
			if !ok {
				return
			}
			fmt.Fprintf(conn, "DROP/1 RESPONSE %s\n", nonce)
		}()
	}
}

// UDPResponder answers authenticated STUN Binding Requests.
//
// It must run on the very socket the client advertises in U4/U6, or the test
// measures a different port than the one that matters. In a real client this
// shares the socket with ADC search results, demultiplexed on the first byte:
// STUN has its top two bits zero and a fixed magic cookie, while ADC messages
// begin with an ASCII letter.
type UDPResponder struct {
	conn *net.UDPConn

	// credential returns the password for a username, and is what lets the
	// client refuse to answer strangers. Without it every DC client becomes an
	// open reflector that an attacker can point anywhere with a spoofed source.
	credential func(username string) (string, bool)
}

// ListenUDP starts a responder.
func ListenUDP(network, address string, credential func(string) (string, bool)) (*UDPResponder, error) {
	addr, err := net.ResolveUDPAddr(network, address)
	if err != nil {
		return nil, err
	}
	conn, err := net.ListenUDP(network, addr)
	if err != nil {
		return nil, err
	}
	r := &UDPResponder{conn: conn, credential: credential}
	go r.serve()
	return r, nil
}

// Port reports the bound port.
func (r *UDPResponder) Port() int {
	ap, err := netip.ParseAddrPort(r.conn.LocalAddr().String())
	if err != nil {
		return 0
	}
	return int(ap.Port())
}

// Close stops the responder.
func (r *UDPResponder) Close() error { return r.conn.Close() }

func (r *UDPResponder) serve() {
	buf := make([]byte, 1500)
	for {
		n, from, err := r.conn.ReadFromUDP(buf)
		if err != nil {
			return
		}

		// Demultiplex: anything that is not STUN belongs to the application
		// sharing this socket.
		if !stun.Looks(buf[:n]) {
			continue
		}
		msg, err := stun.Decode(buf[:n])
		if err != nil || msg.Type != stun.BindingRequest {
			continue
		}

		username, ok := msg.Username()
		if !ok {
			continue
		}
		password, known := r.credential(username)
		if !known {
			continue
		}
		// Unauthenticated datagrams are ignored in silence. Answering them
		// would make this an open reflector.
		if !msg.CheckMessageIntegrity([]byte(password)) {
			continue
		}

		resp := stun.NewResponse(msg)
		resp.AddXORAddress(stun.AttrXORMappedAddress, from.AddrPort())
		resp.AddMessageIntegritySHA256([]byte(password))
		resp.AddMessageIntegrity([]byte(password))
		resp.AddFingerprint()
		_, _ = r.conn.WriteToUDP(resp.Encode(), from)
	}
}

// --- egress -----------------------------------------------------------------

// EgressResult is one port's outcome.
type EgressResult struct {
	Port    int    `json:"port"`
	Reached bool   `json:"reached"`
	Detail  string `json:"detail,omitempty"`
}

// TestEgress checks outbound reachability of the server's banner ports.
//
// A bare connect is never accepted as proof: the usual cause of blocked egress
// is a transparent proxy that accepts the connection itself, so the banner
// must be seen.
func (c *Client) TestEgress(ctx context.Context, doc *ServerDoc) []EgressResult {
	host := doc.Egress.IPv4
	network := "tcp4"
	if c.Family == IPv6 {
		host = doc.Egress.IPv6
		network = "tcp6"
	}
	if host == "" {
		return nil
	}

	var out []EgressResult
	for _, port := range doc.Egress.BannerPorts {
		out = append(out, c.testEgressBanner(ctx, network, host, port))
	}
	return out
}

func (c *Client) testEgressBanner(ctx context.Context, network, host string, port int) EgressResult {
	res := EgressResult{Port: port}

	dialer := &net.Dialer{Timeout: 5 * time.Second}
	if c.LocalAddr.IsValid() {
		dialer.LocalAddr = &net.TCPAddr{IP: c.LocalAddr.AsSlice()}
	}
	conn, err := dialer.DialContext(ctx, network, net.JoinHostPort(host, fmt.Sprint(port)))
	if err != nil {
		res.Detail = "connection failed"
		return res
	}
	defer conn.Close()

	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	buf := make([]byte, 64)
	n, err := conn.Read(buf)
	if err != nil {
		res.Detail = "connected but no banner: something intercepted the connection"
		return res
	}
	got := strings.TrimSpace(string(buf[:n]))
	want := strings.TrimSpace(fmt.Sprintf("DROP/1 EGRESS %d", port))
	if got != want {
		res.Detail = "connected but the banner was wrong: something intercepted the connection"
		return res
	}
	res.Reached = true
	return res
}

// DiscoverNAT runs RFC 5780 behaviour discovery against the session's server.
func (c *Client) DiscoverNAT(ctx context.Context, sess *SessionDoc, localPort int) (natdisc.Result, error) {
	primary, ok := sess.STUN.Primary.AddrPort(c.Family)
	if !ok {
		return natdisc.Result{}, fmt.Errorf("drop: the server advertises no %s STUN endpoint", c.Family)
	}
	return natdisc.Discover(ctx, natdisc.Config{
		Primary:   primary,
		LocalAddr: c.LocalAddr,
		Username:  sess.Creds.Username,
		Password:  sess.Creds.Password,
		Timeout:   3 * time.Second,
	})
}
