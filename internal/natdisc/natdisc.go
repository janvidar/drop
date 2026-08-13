// Package natdisc performs client-side NAT behaviour discovery (RFC 5780).
//
// It answers "would hole punching work", which is a different question from
// "can strangers reach my UDP port". Every request here is client-initiated
// and therefore traverses a mapping the client just created, so a good result
// says nothing about unsolicited inbound traffic -- that is what the DROP
// inbound UDP probe is for, and the two must never be substituted for each
// other.
package natdisc

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"time"

	"quickdc.org/drop/internal/stun"
)

// Behaviour is an RFC 4787 classification.
type Behaviour string

const (
	EndpointIndependent     Behaviour = "endpoint-independent"
	AddressDependent        Behaviour = "address-dependent"
	AddressAndPortDependent Behaviour = "address-and-port-dependent"

	// NoNAT means the mapped address equals the local one.
	NoNAT Behaviour = "none"
	// Blocked means nothing answered at all, so outbound UDP is not getting
	// out. Common on corporate and campus networks, and it means UDP search
	// results will never work regardless of anything else.
	Blocked Behaviour = "blocked"
	// Unknown means the server did not support the tests needed to classify.
	Unknown Behaviour = "unknown"
)

// Result is what discovery established.
type Result struct {
	Mapping   Behaviour `json:"mapping"`
	Filtering Behaviour `json:"filtering"`

	// PortPreserving reports whether the NAT kept the source port.
	PortPreserving bool `json:"port_preserving"`

	LocalAddr  netip.AddrPort `json:"local_addr"`
	MappedAddr netip.AddrPort `json:"mapped_addr"`

	// OtherAddress is the server's advertised alternate endpoint. Its absence
	// means the server cannot do behaviour discovery at all.
	OtherAddress netip.AddrPort `json:"other_address,omitempty"`

	Notes []string `json:"notes,omitempty"`
}

// HolePunchLikely reports whether UDP hole punching -- and therefore ADC's
// NATT extension -- has a realistic chance for this client.
func (r Result) HolePunchLikely() bool {
	if r.Mapping == NoNAT {
		return true
	}
	return r.Mapping == EndpointIndependent &&
		(r.Filtering == EndpointIndependent || r.Filtering == AddressDependent)
}

// Summary explains the result in the words every client should use.
func (r Result) Summary() string {
	switch {
	case r.Mapping == Blocked:
		return "Outbound UDP is blocked entirely. UDP search results cannot " +
			"work on this network."
	case r.Mapping == NoNAT:
		return "No NAT is in the path."
	case r.HolePunchLikely():
		return "Your NAT is well behaved: hole punching has a good chance of " +
			"working with other clients."
	default:
		return "Your NAT assigns a different external port per destination, so " +
			"hole punching will not work reliably. A forwarded port is the only " +
			"dependable option."
	}
}

// Config parameterises discovery.
type Config struct {
	// Primary is the server's primary STUN endpoint.
	Primary netip.AddrPort
	// LocalAddr optionally pins the source address.
	LocalAddr netip.Addr
	// Username and Password are optional short-term credentials.
	Username, Password string
	// Timeout bounds each individual request.
	Timeout time.Duration
}

func (c Config) timeout() time.Duration {
	if c.Timeout <= 0 {
		return 3 * time.Second
	}
	return c.Timeout
}

// Discover runs the mapping and filtering tests.
func Discover(ctx context.Context, cfg Config) (Result, error) {
	res := Result{Mapping: Unknown, Filtering: Unknown}

	mapConn, err := listen(cfg)
	if err != nil {
		return res, err
	}
	defer mapConn.Close()

	res.LocalAddr = localAddrPort(mapConn)

	// --- RFC 5780 section 4.3, mapping behaviour ---------------------------

	// Test I: the primary endpoint, no flags.
	first, _, err := request(ctx, mapConn, cfg, cfg.Primary, false, false)
	if err != nil {
		res.Mapping = Blocked
		res.Filtering = Blocked
		res.Notes = append(res.Notes, "No reply from the primary STUN endpoint.")
		return res, nil
	}

	mapped, ok := first.XORMappedAddress()
	if !ok {
		return res, errors.New("natdisc: the server returned no XOR-MAPPED-ADDRESS")
	}
	res.MappedAddr = mapped
	res.PortPreserving = mapped.Port() == res.LocalAddr.Port()

	if mapped.Addr() == res.LocalAddr.Addr() {
		// The mapped address is our own, so nothing is translating.
		res.Mapping = NoNAT
		res.Filtering = filtering(ctx, cfg, first, &res)
		return res, nil
	}

	other, hasOther := first.PlainAddress(stun.AttrOtherAddress)
	if !hasOther {
		res.Notes = append(res.Notes,
			"The server does not advertise OTHER-ADDRESS, so it cannot classify "+
				"NAT behaviour. Most public STUN servers cannot.")
		return res, nil
	}
	// A server whose alternate address is not genuinely different cannot
	// distinguish anything, and trusting it produces a confident wrong answer.
	if other.Addr() == cfg.Primary.Addr() {
		res.Notes = append(res.Notes,
			"The server's OTHER-ADDRESS is not a different address; behaviour "+
				"discovery would be meaningless and was skipped.")
		return res, nil
	}
	res.OtherAddress = other

	// Test II: the alternate address, the primary port.
	secondTarget := netip.AddrPortFrom(other.Addr(), cfg.Primary.Port())
	second, _, err := request(ctx, mapConn, cfg, secondTarget, false, false)
	if err != nil {
		res.Notes = append(res.Notes,
			"No reply from the alternate address; mapping could not be classified.")
		return res, nil
	}
	secondMapped, _ := second.XORMappedAddress()
	if secondMapped == mapped {
		res.Mapping = EndpointIndependent
	} else {
		// Test III: the alternate address and the alternate port.
		third, _, err := request(ctx, mapConn, cfg, other, false, false)
		if err != nil {
			res.Notes = append(res.Notes,
				"No reply from the alternate address and port; mapping could not "+
					"be fully classified.")
			return res, nil
		}
		thirdMapped, _ := third.XORMappedAddress()
		if thirdMapped == secondMapped {
			res.Mapping = AddressDependent
		} else {
			res.Mapping = AddressAndPortDependent
		}
	}

	res.Filtering = filtering(ctx, cfg, first, &res)
	return res, nil
}

// filtering runs RFC 5780 section 4.4.
//
// It uses a fresh socket, which matters: the mapping tests above deliberately
// contacted the alternate address, and a NAT that saw that would now permit
// return traffic from it. Reusing the socket would classify almost every NAT
// as endpoint-independent-filtering.
func filtering(ctx context.Context, cfg Config, first *stun.Message, res *Result) Behaviour {
	conn, err := listen(cfg)
	if err != nil {
		return Unknown
	}
	defer conn.Close()

	// Test I on the fresh socket, to establish the mapping and confirm the
	// path works before asking for anything unusual.
	if _, _, err := request(ctx, conn, cfg, cfg.Primary, false, false); err != nil {
		return Blocked
	}

	// Test II: ask the server to answer from a different address and port. A
	// reply means the NAT accepts traffic from endpoints the client never
	// contacted.
	_, _, err = request(ctx, conn, cfg, cfg.Primary, true, true)
	if err == nil {
		return EndpointIndependent
	}
	if errors.Is(err, errChangeUnsupported) {
		res.Notes = append(res.Notes,
			"The server does not implement CHANGE-REQUEST, so filtering behaviour "+
				"cannot be determined. Treat it as unknown rather than restrictive.")
		return Unknown
	}

	// Test III: ask only for a different port from the same address.
	_, _, err = request(ctx, conn, cfg, cfg.Primary, false, true)
	if err == nil {
		return AddressDependent
	}
	if errors.Is(err, errChangeUnsupported) {
		res.Notes = append(res.Notes,
			"The server does not implement CHANGE-REQUEST, so filtering behaviour "+
				"cannot be determined. Treat it as unknown rather than restrictive.")
		return Unknown
	}
	return AddressAndPortDependent
}

// errChangeUnsupported marks a server that refused CHANGE-REQUEST.
//
// Distinguishing this from silence is essential. A public STUN server that
// ignores CHANGE-REQUEST looks exactly like the most restrictive NAT there is,
// and reporting that to a user would send them chasing a firewall problem they
// do not have.
var errChangeUnsupported = errors.New("natdisc: server does not support CHANGE-REQUEST")

var errNoReply = errors.New("natdisc: no reply")

func listen(cfg Config) (*net.UDPConn, error) {
	network := "udp4"
	if cfg.Primary.Addr().Is6() {
		network = "udp6"
	}
	var laddr *net.UDPAddr
	if cfg.LocalAddr.IsValid() {
		laddr = &net.UDPAddr{IP: cfg.LocalAddr.AsSlice()}
	}
	return net.ListenUDP(network, laddr)
}

func localAddrPort(conn *net.UDPConn) netip.AddrPort {
	ap, err := netip.ParseAddrPort(conn.LocalAddr().String())
	if err != nil {
		return netip.AddrPort{}
	}
	return netip.AddrPortFrom(ap.Addr().Unmap(), ap.Port())
}

// request sends one Binding Request and waits for the matching response.
//
// Responses are matched by transaction id and not by source address, because
// the filtering tests exist precisely to see whether a reply arrives from an
// address the client never wrote to.
func request(ctx context.Context, conn *net.UDPConn, cfg Config, to netip.AddrPort, changeIP, changePort bool) (*stun.Message, netip.AddrPort, error) {
	var tx stun.TxID
	if _, err := rand.Read(tx[:]); err != nil {
		return nil, netip.AddrPort{}, err
	}

	m := stun.NewRequest(tx)
	if changeIP || changePort {
		var flags uint32
		if changeIP {
			flags |= stun.ChangeIP
		}
		if changePort {
			flags |= stun.ChangePort
		}
		m.AddUint32(stun.AttrChangeRequest, flags)
	}
	if cfg.Username != "" {
		m.AddString(stun.AttrUsername, cfg.Username)
		m.AddMessageIntegritySHA256([]byte(cfg.Password))
		m.AddMessageIntegrity([]byte(cfg.Password))
	}
	m.AddFingerprint()
	wire := m.Encode()

	deadline := time.Now().Add(cfg.timeout())
	if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
		deadline = d
	}

	// A single lost datagram must not be read as a restrictive NAT, so an
	// unanswered request is repeated before giving up.
	attempts := []time.Duration{0, 300 * time.Millisecond, 900 * time.Millisecond}
	buf := make([]byte, 1500)
	start := time.Now()
	next := 0

	for time.Now().Before(deadline) {
		if next < len(attempts) && !time.Now().Before(start.Add(attempts[next])) {
			if _, err := conn.WriteToUDP(wire, net.UDPAddrFromAddrPort(to)); err != nil {
				return nil, netip.AddrPort{}, err
			}
			next++
		}

		wake := deadline
		if next < len(attempts) {
			if t := start.Add(attempts[next]); t.Before(wake) {
				wake = t
			}
		}
		_ = conn.SetReadDeadline(wake)

		n, from, err := conn.ReadFromUDP(buf)
		if err != nil {
			continue
		}
		if !stun.Looks(buf[:n]) {
			continue
		}
		msg, err := stun.Decode(buf[:n])
		if err != nil || msg.TxID != tx {
			continue
		}
		if !msg.CheckFingerprint() {
			continue
		}
		if cfg.Password != "" && msg.Has(stun.AttrMessageIntegrity) {
			if !msg.CheckMessageIntegrity([]byte(cfg.Password)) {
				continue
			}
		}

		fromAP := from.AddrPort()
		fromAP = netip.AddrPortFrom(fromAP.Addr().Unmap().WithZone(""), fromAP.Port())

		if msg.Type == stun.BindingError {
			code, reason, _ := msg.ErrorCode()
			if (changeIP || changePort) && code == stun.CodeBadRequest {
				return nil, fromAP, errChangeUnsupported
			}
			return nil, fromAP, fmt.Errorf("natdisc: %d %s", code, reason)
		}
		return msg, fromAP, nil
	}
	return nil, netip.AddrPort{}, errNoReply
}
