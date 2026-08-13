package stunsrv

import (
	"context"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"testing"
	"time"

	"quickdc.org/drop/internal/natdisc"
	"quickdc.org/drop/internal/stun"
)

// startServer brings up a full four-socket STUN server on loopback.
//
// Linux hands out the whole of 127/8 locally, so 127.0.0.1 and 127.0.0.2 form
// a genuine two-address deployment and the complete RFC 5780 classification
// can be exercised in CI with no public address at all. This is the main
// reason behaviour discovery is worth building test-first: the alternative is
// discovering an encoding mistake against a live droplet.
func startServer(t *testing.T, withAlternate bool) *Server {
	t.Helper()

	primary := netip.MustParseAddr("127.0.0.1")
	alternate := netip.MustParseAddr("127.0.0.2")

	eps := []*Endpoint{
		{Role: Role{}, Bind: netip.AddrPortFrom(primary, 0)},
	}
	if withAlternate {
		eps = append(eps,
			&Endpoint{Role: Role{AltAddr: true}, Bind: netip.AddrPortFrom(alternate, 0)},
			&Endpoint{Role: Role{AltPort: true}, Bind: netip.AddrPortFrom(primary, 0)},
			&Endpoint{Role: Role{AltAddr: true, AltPort: true}, Bind: netip.AddrPortFrom(alternate, 0)},
		)
	}

	s := &Server{
		Family:    "ipv4",
		Endpoints: eps,
		Software:  "dropd-test",
		Log:       slog.New(slog.NewTextHandler(io.Discard, nil)),
	}
	if err := s.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })

	// Ports were assigned by the kernel, so the advertised addresses can only
	// be filled in after binding.
	for _, e := range s.Endpoints {
		e.Advertise = e.LocalAddr()
	}
	return s
}

func primaryAddr(s *Server) netip.AddrPort { return s.byRole(Role{}).LocalAddr() }

func TestBindingRequest(t *testing.T) {
	s := startServer(t, true)

	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	req := stun.NewRequest(stun.TxID{1, 2, 3})
	req.AddFingerprint()
	if _, err := conn.WriteToUDP(req.Encode(), net.UDPAddrFromAddrPort(primaryAddr(s))); err != nil {
		t.Fatal(err)
	}

	conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 1500)
	n, _, err := conn.ReadFromUDP(buf)
	if err != nil {
		t.Fatal(err)
	}
	msg, err := stun.Decode(buf[:n])
	if err != nil {
		t.Fatal(err)
	}
	if msg.Type != stun.BindingResponse {
		t.Fatalf("type = 0x%04x, want a success response", msg.Type)
	}
	mapped, ok := msg.XORMappedAddress()
	if !ok {
		t.Fatal("no XOR-MAPPED-ADDRESS")
	}
	if mapped.String() != conn.LocalAddr().String() {
		t.Errorf("mapped = %v, want %v", mapped, conn.LocalAddr())
	}
	if _, ok := msg.PlainAddress(stun.AttrOtherAddress); !ok {
		t.Error("OTHER-ADDRESS should be advertised when an alternate exists")
	}
	if _, ok := msg.PlainAddress(stun.AttrResponseOrigin); !ok {
		t.Error("RESPONSE-ORIGIN should always be present")
	}
	if !msg.CheckFingerprint() {
		t.Error("the response fingerprint should verify")
	}
}

// Without a second address, the server must not advertise OTHER-ADDRESS: its
// presence is exactly how a client decides behaviour discovery is available.
func TestNoOtherAddressWithoutAlternate(t *testing.T) {
	s := startServer(t, false)
	if s.HasAlternate() {
		t.Fatal("HasAlternate should be false")
	}

	msg := roundTrip(t, primaryAddr(s), false, false)
	if _, ok := msg.PlainAddress(stun.AttrOtherAddress); ok {
		t.Error("OTHER-ADDRESS must not be advertised without a real alternate")
	}
}

// CHANGE-REQUEST is the half of RFC 5780 that public servers ignore. Ignoring
// it is not a harmless omission: answering from the original socket looks to a
// client exactly like a NAT that permitted the changed source, so it would
// classify filtering as endpoint-independent when it is not. Refusing is the
// only honest option.
func TestChangeRequestRefusedWithoutAlternate(t *testing.T) {
	s := startServer(t, false)

	msg := roundTrip(t, primaryAddr(s), true, true)
	if msg.Type != stun.BindingError {
		t.Fatalf("type = 0x%04x, want an error response", msg.Type)
	}
	code, _, _ := msg.ErrorCode()
	if code != stun.CodeBadRequest {
		t.Errorf("code = %d, want 400", code)
	}
}

// The response must come from a genuinely different socket, or the whole
// filtering test is a lie.
func TestChangeRequestAnswersFromAnotherEndpoint(t *testing.T) {
	s := startServer(t, true)

	cases := []struct {
		name                 string
		changeIP, changePort bool
		wantRole             Role
	}{
		{"change port only", false, true, Role{AltPort: true}},
		{"change address only", true, false, Role{AltAddr: true}},
		{"change both", true, true, Role{AltAddr: true, AltPort: true}},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
			if err != nil {
				t.Fatal(err)
			}
			defer conn.Close()

			req := stun.NewRequest(stun.TxID{9, 9, 9})
			var flags uint32
			if c.changeIP {
				flags |= stun.ChangeIP
			}
			if c.changePort {
				flags |= stun.ChangePort
			}
			req.AddUint32(stun.AttrChangeRequest, flags)
			req.AddFingerprint()
			conn.WriteToUDP(req.Encode(), net.UDPAddrFromAddrPort(primaryAddr(s)))

			conn.SetReadDeadline(time.Now().Add(2 * time.Second))
			buf := make([]byte, 1500)
			n, from, err := conn.ReadFromUDP(buf)
			if err != nil {
				t.Fatalf("no reply: %v", err)
			}

			want := s.byRole(c.wantRole).LocalAddr()
			if from.AddrPort().String() != want.String() {
				t.Errorf("reply came from %v, want %v", from, want)
			}

			msg, err := stun.Decode(buf[:n])
			if err != nil {
				t.Fatal(err)
			}
			origin, ok := msg.PlainAddress(stun.AttrResponseOrigin)
			if !ok || origin != want {
				t.Errorf("RESPONSE-ORIGIN = %v (ok=%v), want %v", origin, ok, want)
			}
		})
	}
}

// The full client-side classification against the real server. On loopback
// there is no NAT, so this is the "none" path -- but every message, attribute
// and socket transition on the way is the same code that runs in production.
func TestBehaviourDiscoveryEndToEnd(t *testing.T) {
	s := startServer(t, true)

	res, err := natdisc.Discover(context.Background(), natdisc.Config{
		Primary:   primaryAddr(s),
		LocalAddr: netip.MustParseAddr("127.0.0.1"),
		Timeout:   2 * time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}

	// Loopback is not translated, so the mapped address is our own.
	if res.Mapping != natdisc.NoNAT {
		t.Errorf("mapping = %q, want none on loopback", res.Mapping)
	}
	if !res.PortPreserving {
		t.Error("loopback must preserve the port")
	}
	// Filtering is still exercised for real: it needs CHANGE-REQUEST to work
	// across all four sockets.
	if res.Filtering != natdisc.EndpointIndependent {
		t.Errorf("filtering = %q, want endpoint-independent on loopback", res.Filtering)
	}
	if !res.HolePunchLikely() {
		t.Error("hole punching should be considered likely with no NAT")
	}
	if res.Summary() == "" {
		t.Error("a result must always carry a summary")
	}
}

// A server without CHANGE-REQUEST must produce "unknown" filtering, never
// "address-and-port-dependent". Reporting the latter would send users chasing
// a firewall problem they do not have -- exactly what happens today against
// public STUN servers.
func TestBehaviourDiscoveryUnknownWithoutChangeSupport(t *testing.T) {
	s := startServer(t, false)

	res, err := natdisc.Discover(context.Background(), natdisc.Config{
		Primary:   primaryAddr(s),
		LocalAddr: netip.MustParseAddr("127.0.0.1"),
		Timeout:   time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	if res.Filtering == natdisc.AddressAndPortDependent {
		t.Error("a server without CHANGE-REQUEST must not be reported as a " +
			"restrictive NAT")
	}
	if len(res.Notes) == 0 {
		t.Error("the client should explain why classification was not possible")
	}
}

func TestAuthentication(t *testing.T) {
	s := startServer(t, true)
	s.Credentials = func(u string) (string, bool) {
		if u == "good-user" {
			return "good-pass", true
		}
		return "", false
	}

	t.Run("valid credentials", func(t *testing.T) {
		msg := roundTripAuth(t, primaryAddr(s), "good-user", "good-pass")
		if msg.Type != stun.BindingResponse {
			t.Fatalf("type = 0x%04x, want success", msg.Type)
		}
		// An authenticated request deserves an authenticated answer, or the
		// client cannot tell it from an off-path forgery.
		if !msg.CheckMessageIntegrity([]byte("good-pass")) {
			t.Error("the response should be authenticated")
		}
	})

	t.Run("wrong password", func(t *testing.T) {
		msg := roundTripAuth(t, primaryAddr(s), "good-user", "wrong-pass")
		if msg.Type != stun.BindingError {
			t.Fatalf("type = 0x%04x, want an error", msg.Type)
		}
		if code, _, _ := msg.ErrorCode(); code != stun.CodeUnauthorized {
			t.Errorf("code = %d, want 401", code)
		}
	})

	t.Run("unknown username", func(t *testing.T) {
		msg := roundTripAuth(t, primaryAddr(s), "nobody", "any")
		if msg.Type != stun.BindingError {
			t.Fatalf("type = 0x%04x, want an error", msg.Type)
		}
	})

	t.Run("anonymous still works", func(t *testing.T) {
		// Standard STUN allows unauthenticated Binding Requests, and the
		// mapping tests must work before any session exists.
		msg := roundTrip(t, primaryAddr(s), false, false)
		if msg.Type != stun.BindingResponse {
			t.Errorf("type = 0x%04x, want success", msg.Type)
		}
	})
}

// Anything that is not a STUN Binding Request must be met with silence. This
// socket is on the public internet and will receive scans; replying would make
// the service a reflector.
func TestNonSTUNIsIgnored(t *testing.T) {
	s := startServer(t, true)

	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	target := net.UDPAddrFromAddrPort(primaryAddr(s))

	junk := [][]byte{
		[]byte("hello"),
		[]byte("URES AAAABBBBCCCC SI123\n"),
		make([]byte, 1200),
		stun.NewResponse(&stun.Message{TxID: stun.TxID{1}}).Encode(), // a response, not a request
	}
	for _, b := range junk {
		conn.WriteToUDP(b, target)
	}

	conn.SetReadDeadline(time.Now().Add(300 * time.Millisecond))
	buf := make([]byte, 1500)
	if n, _, err := conn.ReadFromUDP(buf); err == nil {
		t.Errorf("server replied to junk with %d bytes", n)
	}
}

func TestUnknownComprehensionRequiredAttribute(t *testing.T) {
	s := startServer(t, true)

	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	req := stun.NewRequest(stun.TxID{4, 4, 4})
	req.Add(0x7ABC, []byte{1, 2, 3, 4}) // comprehension-required, unknown
	req.AddFingerprint()
	conn.WriteToUDP(req.Encode(), net.UDPAddrFromAddrPort(primaryAddr(s)))

	conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 1500)
	n, _, err := conn.ReadFromUDP(buf)
	if err != nil {
		t.Fatal(err)
	}
	msg, _ := stun.Decode(buf[:n])
	if code, _, _ := msg.ErrorCode(); code != stun.CodeUnknownAttr {
		t.Errorf("code = %d, want 420", code)
	}
}

// The bind/advertise split, which is what makes a DigitalOcean Reserved IP
// usable: the socket binds an address the outside world never sees, and the
// advertised value must be what goes on the wire.
func TestAdvertisedAddressIsUsedNotBound(t *testing.T) {
	primary := netip.MustParseAddr("127.0.0.1")
	alternate := netip.MustParseAddr("127.0.0.2")
	fakePublic := netip.MustParseAddrPort("198.51.100.11:3479")

	s := &Server{
		Family: "ipv4",
		Endpoints: []*Endpoint{
			{Role: Role{}, Bind: netip.AddrPortFrom(primary, 0)},
			{Role: Role{AltAddr: true}, Bind: netip.AddrPortFrom(alternate, 0)},
			{Role: Role{AltPort: true}, Bind: netip.AddrPortFrom(primary, 0)},
			{Role: Role{AltAddr: true, AltPort: true}, Bind: netip.AddrPortFrom(alternate, 0),
				Advertise: fakePublic},
		},
		Log: slog.New(slog.NewTextHandler(io.Discard, nil)),
	}
	if err := s.Start(); err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	for _, e := range s.Endpoints {
		if !e.Advertise.IsValid() {
			e.Advertise = e.LocalAddr()
		}
	}

	msg := roundTrip(t, primaryAddr(s), false, false)
	other, ok := msg.PlainAddress(stun.AttrOtherAddress)
	if !ok {
		t.Fatal("no OTHER-ADDRESS")
	}
	if other != fakePublic {
		t.Errorf("OTHER-ADDRESS = %v, want the advertised %v, not the bound address",
			other, fakePublic)
	}
}

func TestStartRequiresPrimary(t *testing.T) {
	s := &Server{
		Family:    "ipv4",
		Endpoints: []*Endpoint{{Role: Role{AltAddr: true}, Bind: netip.MustParseAddrPort("127.0.0.2:0")}},
	}
	if err := s.Start(); err == nil {
		s.Close()
		t.Fatal("a server without a primary endpoint must not start")
	}
}

func TestRoleString(t *testing.T) {
	seen := map[string]bool{}
	for _, r := range []Role{{}, {AltAddr: true}, {AltPort: true}, {AltAddr: true, AltPort: true}} {
		s := r.String()
		if s == "" || seen[s] {
			t.Errorf("role %v has a missing or duplicate name %q", r, s)
		}
		seen[s] = true
	}
}

// --- helpers ---------------------------------------------------------------

func roundTrip(t *testing.T, to netip.AddrPort, changeIP, changePort bool) *stun.Message {
	t.Helper()
	return send(t, to, func(m *stun.Message) {
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
	})
}

func roundTripAuth(t *testing.T, to netip.AddrPort, user, pass string) *stun.Message {
	t.Helper()
	return send(t, to, func(m *stun.Message) {
		m.AddString(stun.AttrUsername, user)
		m.AddMessageIntegrity([]byte(pass))
	})
}

func send(t *testing.T, to netip.AddrPort, build func(*stun.Message)) *stun.Message {
	t.Helper()
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	req := stun.NewRequest(stun.TxID{7, 7, 7})
	build(req)
	req.AddFingerprint()
	if _, err := conn.WriteToUDP(req.Encode(), net.UDPAddrFromAddrPort(to)); err != nil {
		t.Fatal(err)
	}

	conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 1500)
	n, _, err := conn.ReadFromUDP(buf)
	if err != nil {
		t.Fatalf("no reply: %v", err)
	}
	msg, err := stun.Decode(buf[:n])
	if err != nil {
		t.Fatal(err)
	}
	return msg
}
