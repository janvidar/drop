// Package stunsrv implements the STUN server side, including RFC 5780 NAT
// behaviour discovery.
//
// Behaviour discovery is why DROP runs its own STUN server rather than
// pointing clients at a public one. Measured against five public servers in
// August 2026, three returned no OTHER-ADDRESS at all and the two that did
// ignored CHANGE-REQUEST entirely -- so the mapping half of RFC 5780 is widely
// available and the filtering half effectively is not. A DROP server that
// advertises "nat" must implement both.
package stunsrv

import (
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"sync"

	"quickdc.org/drop/internal/stun"
)

// Role identifies which of the four sockets a request arrived on.
//
// RFC 5780 needs all four combinations of two addresses and two ports, because
// that is what lets a client tell endpoint-independent mapping from
// address-dependent from address-and-port-dependent.
type Role struct {
	AltAddr bool
	AltPort bool
}

func (r Role) String() string {
	switch {
	case !r.AltAddr && !r.AltPort:
		return "primary"
	case r.AltAddr && !r.AltPort:
		return "alt-addr"
	case !r.AltAddr && r.AltPort:
		return "alt-port"
	default:
		return "alt-both"
	}
}

// Endpoint is one bound socket.
//
// Bind and Advertise differ whenever a provider delivers a secondary address
// by translating it to a hidden anchor -- DigitalOcean Reserved IPs being the
// case this was built against. RESPONSE-ORIGIN and OTHER-ADDRESS must carry
// what the outside world sees, which the socket itself cannot tell us.
type Endpoint struct {
	Role      Role
	Bind      netip.AddrPort
	Advertise netip.AddrPort

	conn *net.UDPConn
}

// CredentialFunc resolves a USERNAME to its short-term password.
//
// Returning false means the username is unknown or expired, and the request is
// answered with a 401.
type CredentialFunc func(username string) (password string, ok bool)

// Server serves STUN on one address family.
type Server struct {
	// Family is "ipv4" or "ipv6", used only for logging and metrics.
	Family string
	// Endpoints must contain the primary; the other three are needed for
	// behaviour discovery and may be absent without it.
	Endpoints []*Endpoint
	// Credentials authenticates requests. When nil, the server answers
	// unauthenticated Binding Requests, which is standard STUN behaviour and
	// what makes the mapping tests usable before a session exists.
	Credentials CredentialFunc
	// Software is advertised in responses.
	Software string
	Log      *slog.Logger

	// OnRequest is called for each served request, for metrics.
	OnRequest func(role Role, outcome string)

	mu      sync.Mutex
	started bool
	wg      sync.WaitGroup
}

// byRole indexes the endpoints so a handler can find the socket it must answer
// from when CHANGE-REQUEST asks for a different address or port.
func (s *Server) byRole(r Role) *Endpoint {
	for _, e := range s.Endpoints {
		if e.Role == r {
			return e
		}
	}
	return nil
}

// HasAlternate reports whether behaviour discovery is possible, which requires
// all four sockets.
func (s *Server) HasAlternate() bool {
	for _, r := range []Role{{true, false}, {false, true}, {true, true}} {
		if s.byRole(r) == nil {
			return false
		}
	}
	return true
}

// Start binds every endpoint and begins serving.
func (s *Server) Start() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.started {
		return errors.New("stunsrv: already started")
	}
	if s.byRole(Role{}) == nil {
		return errors.New("stunsrv: no primary endpoint configured")
	}

	network := "udp4"
	if s.Family == "ipv6" {
		network = "udp6"
	}

	for _, e := range s.Endpoints {
		conn, err := net.ListenUDP(network, net.UDPAddrFromAddrPort(e.Bind))
		if err != nil {
			s.closeAllLocked()
			return fmt.Errorf("stunsrv: binding %s (%s): %w", e.Bind, e.Role, err)
		}
		e.conn = conn
	}

	for _, e := range s.Endpoints {
		s.wg.Add(1)
		go func(e *Endpoint) {
			defer s.wg.Done()
			s.serve(e)
		}(e)
	}
	s.started = true
	return nil
}

// Close stops the server and waits for its goroutines.
func (s *Server) Close() error {
	s.mu.Lock()
	s.closeAllLocked()
	s.started = false
	s.mu.Unlock()
	s.wg.Wait()
	return nil
}

func (s *Server) closeAllLocked() {
	for _, e := range s.Endpoints {
		if e.conn != nil {
			e.conn.Close()
			e.conn = nil
		}
	}
}

// LocalAddr returns the actual bound address of an endpoint, which differs
// from the configured one when the port was zero (as in tests).
func (e *Endpoint) LocalAddr() netip.AddrPort {
	if e.conn == nil {
		return e.Bind
	}
	ap, err := netip.ParseAddrPort(e.conn.LocalAddr().String())
	if err != nil {
		return e.Bind
	}
	return ap
}

func (s *Server) serve(e *Endpoint) {
	// One datagram buffer per socket. STUN messages are small; anything that
	// does not fit is not a STUN message.
	buf := make([]byte, 1500)
	for {
		n, from, err := e.conn.ReadFromUDP(buf)
		if err != nil {
			return // the socket was closed
		}
		s.handle(e, buf[:n], from)
	}
}

func (s *Server) handle(e *Endpoint, datagram []byte, from *net.UDPAddr) {
	outcome := "ignored"
	defer func() {
		if s.OnRequest != nil {
			s.OnRequest(e.Role, outcome)
		}
	}()

	// Anything that is not STUN is dropped in silence. This socket is on the
	// public internet and will receive scans and stray traffic; replying to
	// them would make the service a reflector.
	if !stun.Looks(datagram) {
		return
	}
	msg, err := stun.Decode(datagram)
	if err != nil {
		return
	}
	if msg.Type != stun.BindingRequest {
		// Responses and indications need no reply. Answering a response would
		// let two servers ping-pong forever.
		return
	}
	if !msg.CheckFingerprint() {
		return
	}

	fromAP := from.AddrPort()
	fromAP = netip.AddrPortFrom(fromAP.Addr().Unmap().WithZone(""), fromAP.Port())

	// Comprehension-required attributes we do not understand must be refused
	// with a 420 rather than silently ignored (RFC 8489 section 6.3.1).
	if unknown := msg.UnknownRequired(); len(unknown) > 0 {
		resp := stun.NewError(msg, stun.CodeUnknownAttr, "Unknown Attribute")
		v := make([]byte, 0, len(unknown)*2)
		for _, a := range unknown {
			v = append(v, byte(a>>8), byte(a))
		}
		resp.Add(stun.AttrUnknownAttributes, v)
		s.reply(e, e, resp, from)
		outcome = "unknown-attribute"
		return
	}

	// Authentication, when the server requires it. A request carrying a
	// USERNAME is always checked, even if credentials are optional, so that a
	// bad credential is reported rather than quietly ignored.
	if s.Credentials != nil {
		if username, ok := msg.Username(); ok {
			password, known := s.Credentials(username)
			if !known || !msg.CheckMessageIntegrity([]byte(password)) {
				s.reply(e, e, stun.NewError(msg, stun.CodeUnauthorized, "Unauthorized"), from)
				outcome = "unauthorized"
				return
			}
		} else if msg.Has(stun.AttrMessageIntegrity) || msg.Has(stun.AttrMessageIntegritySHA256) {
			// Integrity without a username cannot be checked against anything.
			s.reply(e, e, stun.NewError(msg, stun.CodeBadRequest, "Bad Request"), from)
			outcome = "bad-request"
			return
		}
	}

	// CHANGE-REQUEST selects which socket answers. This is the half of RFC
	// 5780 that almost no deployed server implements, and the reason a client
	// cannot get a filtering classification from a public STUN server.
	changeIP, changePort, _ := msg.ChangeRequest()
	respondFrom := e
	if changeIP || changePort {
		want := Role{
			AltAddr: e.Role.AltAddr != changeIP,
			AltPort: e.Role.AltPort != changePort,
		}
		alt := s.byRole(want)
		if alt == nil {
			// Behaviour discovery is not configured. Refusing is important:
			// answering from the original socket would look to the client
			// exactly like a NAT that permitted the changed source, and it
			// would classify filtering as endpoint-independent when it is not.
			s.reply(e, e, stun.NewError(msg, stun.CodeBadRequest,
				"CHANGE-REQUEST is not supported by this server"), from)
			outcome = "change-unsupported"
			return
		}
		respondFrom = alt
	}

	resp := stun.NewResponse(msg)
	resp.AddXORAddress(stun.AttrXORMappedAddress, fromAP)

	// RESPONSE-ORIGIN tells the client which socket actually answered, so it
	// can confirm the change it asked for happened. OTHER-ADDRESS advertises
	// the far corner of the two-by-two grid, and its presence is how a client
	// detects that behaviour discovery is available at all.
	resp.AddAddress(stun.AttrResponseOrigin, respondFrom.Advertise)
	if other := s.byRole(Role{AltAddr: true, AltPort: true}); other != nil {
		resp.AddAddress(stun.AttrOtherAddress, other.Advertise)
	}
	if s.Software != "" {
		resp.AddString(stun.AttrSoftware, s.Software)
	}

	// A response to an authenticated request must itself be authenticated, or
	// the client cannot tell our answer from an off-path forgery.
	if s.Credentials != nil {
		if username, ok := msg.Username(); ok {
			if password, known := s.Credentials(username); known {
				resp.AddMessageIntegritySHA256([]byte(password))
				resp.AddMessageIntegrity([]byte(password))
			}
		}
	}
	resp.AddFingerprint()

	s.reply(e, respondFrom, resp, from)
	outcome = "ok"
}

// reply sends a response from the given endpoint.
func (s *Server) reply(received, from *Endpoint, msg *stun.Message, to *net.UDPAddr) {
	if from.conn == nil {
		return
	}
	if _, err := from.conn.WriteToUDP(msg.Encode(), to); err != nil && s.Log != nil {
		s.Log.Debug("stun reply failed",
			"family", s.Family, "from", from.Role.String(), "error", err)
	}
}
