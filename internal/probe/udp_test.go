package probe

import (
	"context"
	"net"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"

	"quickdc.org/drop/internal/stun"
)

const (
	testUser = "session-id"
	testPass = "session-password"
)

// udpResponder stands in for a DC client's STUN agent on its U4 port.
type udpResponder struct {
	conn     *net.UDPConn
	received atomic.Int64
	port     int
}

// startResponder listens on loopback and answers authenticated Binding
// Requests. behaviour selects how it misbehaves, if at all.
func startResponder(t *testing.T, behaviour string, password string) *udpResponder {
	t.Helper()
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close() })

	r := &udpResponder{conn: conn}
	r.port = int(netip.MustParseAddrPort(conn.LocalAddr().String()).Port())

	go func() {
		buf := make([]byte, 1500)
		for {
			n, from, err := conn.ReadFromUDP(buf)
			if err != nil {
				return
			}
			if !stun.Looks(buf[:n]) {
				continue
			}
			msg, err := stun.Decode(buf[:n])
			if err != nil {
				continue
			}
			r.received.Add(1)

			// A conforming client refuses to answer anything that does not
			// authenticate against a session it just opened.
			if !msg.CheckMessageIntegrity([]byte(password)) {
				continue
			}

			switch behaviour {
			case "silent":
				continue
			case "unauthenticated":
				resp := stun.NewResponse(msg)
				resp.AddXORAddress(stun.AttrXORMappedAddress, from.AddrPort())
				conn.WriteToUDP(resp.Encode(), from)
			case "wrongkey":
				resp := stun.NewResponse(msg)
				resp.AddXORAddress(stun.AttrXORMappedAddress, from.AddrPort())
				resp.AddMessageIntegrity([]byte("not-the-password"))
				conn.WriteToUDP(resp.Encode(), from)
			case "error":
				resp := stun.NewError(msg, stun.CodeUnauthorized, "Unauthorized")
				resp.AddMessageIntegrity([]byte(password))
				conn.WriteToUDP(resp.Encode(), from)
			default:
				resp := stun.NewResponse(msg)
				resp.AddXORAddress(stun.AttrXORMappedAddress, from.AddrPort())
				resp.AddMessageIntegritySHA256([]byte(password))
				resp.AddMessageIntegrity([]byte(password))
				resp.AddFingerprint()
				conn.WriteToUDP(resp.Encode(), from)
			}
		}
	}()
	return r
}

func udpProber() *UDPProber {
	return &UDPProber{
		LocalAddr: netip.MustParseAddr("127.0.0.1"),
		Timeout:   2 * time.Second,
	}
}

func TestProbeUDPOpen(t *testing.T) {
	r := startResponder(t, "ok", testPass)

	res := udpProber().ProbeUDPAll(context.Background(),
		netip.MustParseAddr("127.0.0.1"), []int{r.port}, testUser, testPass)

	if len(res) != 1 {
		t.Fatalf("got %d results", len(res))
	}
	if res[0].Verdict != UDPOpen {
		t.Fatalf("verdict = %q (%s), want open", res[0].Verdict, res[0].Detail)
	}
	if res[0].Port != r.port {
		t.Errorf("port = %d, want %d", res[0].Port, r.port)
	}
	if res[0].RespondedFrom == "" {
		t.Error("responded_from should be recorded")
	}
}

// Nothing listening: no ICMP guarantee, so this must simply be no_response.
func TestProbeUDPNoResponse(t *testing.T) {
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	port := int(netip.MustParseAddrPort(conn.LocalAddr().String()).Port())
	conn.Close()

	p := &UDPProber{LocalAddr: netip.MustParseAddr("127.0.0.1"), Timeout: 600 * time.Millisecond}
	res := p.ProbeUDPAll(context.Background(), netip.MustParseAddr("127.0.0.1"),
		[]int{port}, testUser, testPass)

	if res[0].Verdict != UDPNoResponse {
		t.Fatalf("verdict = %q, want no_response", res[0].Verdict)
	}
}

// A client that receives the probe but stays quiet is indistinguishable from a
// blocked datagram, and must not be reported as open.
func TestProbeUDPSilentClient(t *testing.T) {
	r := startResponder(t, "silent", testPass)

	p := &UDPProber{LocalAddr: netip.MustParseAddr("127.0.0.1"), Timeout: 600 * time.Millisecond}
	res := p.ProbeUDPAll(context.Background(), netip.MustParseAddr("127.0.0.1"),
		[]int{r.port}, testUser, testPass)

	if res[0].Verdict != UDPNoResponse {
		t.Fatalf("verdict = %q, want no_response", res[0].Verdict)
	}
	if r.received.Load() == 0 {
		t.Error("the responder never saw the probe")
	}
}

// The security property: a reply that does not authenticate must not count.
// Otherwise anyone who can observe or guess a transaction id can assert that a
// port is reachable when it is not.
func TestProbeUDPRejectsUnauthenticatedResponse(t *testing.T) {
	for _, behaviour := range []string{"unauthenticated", "wrongkey"} {
		t.Run(behaviour, func(t *testing.T) {
			r := startResponder(t, behaviour, testPass)

			p := &UDPProber{LocalAddr: netip.MustParseAddr("127.0.0.1"), Timeout: 600 * time.Millisecond}
			res := p.ProbeUDPAll(context.Background(), netip.MustParseAddr("127.0.0.1"),
				[]int{r.port}, testUser, testPass)

			if res[0].Verdict == UDPOpen {
				t.Fatal("an unauthenticated response must not produce open")
			}
		})
	}
}

// The probe itself must be authenticated, so that a DC client can refuse to
// answer unsolicited datagrams from strangers. If the prober omitted integrity,
// every client would have to answer anyone.
func TestProbeIsAuthenticated(t *testing.T) {
	r := startResponder(t, "ok", "a-different-password")

	p := &UDPProber{LocalAddr: netip.MustParseAddr("127.0.0.1"), Timeout: 600 * time.Millisecond}
	res := p.ProbeUDPAll(context.Background(), netip.MustParseAddr("127.0.0.1"),
		[]int{r.port}, testUser, testPass)

	if r.received.Load() == 0 {
		t.Fatal("the responder never saw the probe")
	}
	if res[0].Verdict == UDPOpen {
		t.Fatal("a client with different credentials must not validate the probe")
	}
}

func TestProbeUDPClientError(t *testing.T) {
	r := startResponder(t, "error", testPass)

	p := &UDPProber{LocalAddr: netip.MustParseAddr("127.0.0.1"), Timeout: 600 * time.Millisecond}
	res := p.ProbeUDPAll(context.Background(), netip.MustParseAddr("127.0.0.1"),
		[]int{r.port}, testUser, testPass)

	if res[0].Verdict != UDPNoResponse {
		t.Errorf("verdict = %q", res[0].Verdict)
	}
	if res[0].Detail == "" {
		t.Error("an error response should be explained in the detail")
	}
}

func TestProbeUDPMultiplePorts(t *testing.T) {
	a := startResponder(t, "ok", testPass)
	b := startResponder(t, "silent", testPass)

	dead, _ := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	deadPort := int(netip.MustParseAddrPort(dead.LocalAddr().String()).Port())
	dead.Close()

	ports := []int{a.port, b.port, deadPort}
	p := &UDPProber{LocalAddr: netip.MustParseAddr("127.0.0.1"), Timeout: time.Second}
	res := p.ProbeUDPAll(context.Background(), netip.MustParseAddr("127.0.0.1"),
		ports, testUser, testPass)

	if len(res) != 3 {
		t.Fatalf("got %d results, want 3", len(res))
	}
	// Results must line up with the requested ports, or a client attributes a
	// verdict to the wrong port.
	for i, port := range ports {
		if res[i].Port != port {
			t.Errorf("result %d is for port %d, want %d", i, res[i].Port, port)
		}
	}
	if res[0].Verdict != UDPOpen {
		t.Errorf("answering port: verdict = %q, want open", res[0].Verdict)
	}
	if res[1].Verdict != UDPNoResponse || res[2].Verdict != UDPNoResponse {
		t.Errorf("quiet ports: verdicts = %q, %q", res[1].Verdict, res[2].Verdict)
	}
}

// A lost first datagram must not be reported as unreachable: that is the most
// expensive wrong answer the service can give, since it sends the user off to
// reconfigure a firewall that is working.
func TestProbeUDPRetransmits(t *testing.T) {
	if testing.Short() {
		t.Skip("waits for a retransmit")
	}
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	port := int(netip.MustParseAddrPort(conn.LocalAddr().String()).Port())

	var seen atomic.Int64
	go func() {
		buf := make([]byte, 1500)
		for {
			n, from, err := conn.ReadFromUDP(buf)
			if err != nil {
				return
			}
			// Ignore the first datagram entirely, as a lossy path would.
			if seen.Add(1) == 1 {
				continue
			}
			msg, err := stun.Decode(buf[:n])
			if err != nil {
				continue
			}
			resp := stun.NewResponse(msg)
			resp.AddXORAddress(stun.AttrXORMappedAddress, from.AddrPort())
			resp.AddMessageIntegrity([]byte(testPass))
			conn.WriteToUDP(resp.Encode(), from)
		}
	}()

	p := &UDPProber{LocalAddr: netip.MustParseAddr("127.0.0.1"), Timeout: 3 * time.Second}
	res := p.ProbeUDPAll(context.Background(), netip.MustParseAddr("127.0.0.1"),
		[]int{port}, testUser, testPass)

	if res[0].Verdict != UDPOpen {
		t.Fatalf("verdict = %q, want open after a retransmit (datagrams seen: %d)",
			res[0].Verdict, seen.Load())
	}
	if seen.Load() < 2 {
		t.Errorf("only %d datagrams sent; no retransmit happened", seen.Load())
	}
}

func TestProbeUDPEmptyPortList(t *testing.T) {
	res := udpProber().ProbeUDPAll(context.Background(),
		netip.MustParseAddr("127.0.0.1"), nil, testUser, testPass)
	if len(res) != 0 {
		t.Errorf("got %d results for no ports", len(res))
	}
}

func TestSummaryUDP(t *testing.T) {
	for _, v := range []Verdict{UDPOpen, UDPNoResponse, Error} {
		if SummaryUDP(v) == "" {
			t.Errorf("verdict %q has no summary", v)
		}
	}
}
