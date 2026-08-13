package probe

import (
	"context"
	"crypto/rand"
	"fmt"
	"net"
	"net/netip"
	"time"

	"quickdc.org/drop/internal/stun"
)

// UDP verdicts. Unlike TCP there is no refused/filtered distinction to make:
// a blocked datagram and a client that never answers look identical from here.
const (
	// UDPOpen: an authenticated Binding Response came back, so unsolicited
	// inbound UDP demonstrably reaches the client. This is what ADC search
	// results actually require.
	UDPOpen Verdict = "open"
	// UDPNoResponse: nothing came back. The server cannot tell whether the
	// datagram was blocked or the client simply does not implement the
	// responder, so it reports the neutral outcome and lets the client -- which
	// knows which of the two applies -- draw the conclusion.
	UDPNoResponse Verdict = "no_response"
)

// UDPResult is the outcome for one port.
type UDPResult struct {
	Port          int     `json:"port"`
	Verdict       Verdict `json:"verdict"`
	RespondedFrom string  `json:"responded_from,omitempty"`
	RTTMS         int     `json:"rtt_ms,omitempty"`
	Detail        string  `json:"detail,omitempty"`
}

// UDPProber sends unsolicited STUN Binding Requests.
type UDPProber struct {
	// LocalAddr is the address to send from.
	LocalAddr netip.Addr
	// Timeout bounds the whole batch, not each port: all probes share one
	// socket and one read loop.
	Timeout time.Duration
}

// retransmits are the offsets at which an unanswered probe is repeated.
//
// A single lost datagram would otherwise be reported as "no response" and read
// by the user as a blocked firewall, which is the most expensive kind of wrong
// answer this service can give. The schedule is a shortened version of RFC
// 8489's, since the whole inbound test is capped at 15 seconds.
var retransmits = []time.Duration{500 * time.Millisecond, 1500 * time.Millisecond}

type udpProbe struct {
	port    int
	txid    stun.TxID
	request []byte
	sentAt  time.Time
	result  UDPResult
	done    bool
}

// ProbeUDPAll probes every port from a single unsolicited source.
//
// The socket is bound to an ephemeral port the client has certainly never
// contacted, which is what makes this a test of *unsolicited* reachability
// rather than of a NAT mapping the client created itself.
func (p *UDPProber) ProbeUDPAll(ctx context.Context, addr netip.Addr, ports []int, username, password string) []UDPResult {
	results := make([]UDPResult, len(ports))
	for i, port := range ports {
		results[i] = UDPResult{Port: port, Verdict: UDPNoResponse}
	}
	if len(ports) == 0 {
		return results
	}

	conn, err := p.listen()
	if err != nil {
		for i := range results {
			results[i].Verdict = Error
			results[i].Detail = "the server could not open a probe socket"
		}
		return results
	}
	defer conn.Close()

	deadline := time.Now().Add(p.Timeout)
	if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
		deadline = d
	}

	key := []byte(password)
	probes := make([]*udpProbe, len(ports))
	byTx := make(map[stun.TxID]*udpProbe, len(ports))

	for i, port := range ports {
		pr, err := buildProbe(port, username, key)
		if err != nil {
			results[i].Verdict = Error
			results[i].Detail = err.Error()
			continue
		}
		probes[i] = pr
		byTx[pr.txid] = pr
		p.send(conn, addr, pr)
	}

	p.readLoop(conn, addr, byTx, key, deadline)

	for i, pr := range probes {
		if pr != nil {
			results[i] = pr.result
			results[i].Port = ports[i]
		}
	}
	return results
}

func (p *UDPProber) listen() (*net.UDPConn, error) {
	network := "udp4"
	if p.LocalAddr.Is6() {
		network = "udp6"
	}
	var laddr *net.UDPAddr
	if p.LocalAddr.IsValid() {
		laddr = &net.UDPAddr{IP: p.LocalAddr.AsSlice()}
	}
	return net.ListenUDP(network, laddr)
}

func buildProbe(port int, username string, key []byte) (*udpProbe, error) {
	var tx stun.TxID
	if _, err := rand.Read(tx[:]); err != nil {
		return nil, fmt.Errorf("generating a transaction id: %w", err)
	}

	m := stun.NewRequest(tx)
	m.AddString(stun.AttrUsername, username)

	// DROP-PROBE tells the client this is a DROP unsolicited probe rather than
	// ordinary STUN traffic, so it applies the DROP response rules. The value
	// is the probed port, which gives a client something to log.
	m.AddUint32(stun.AttrDropProbe, uint32(port))

	// Both integrity attributes: SHA-256 where the peer supports it, SHA-1
	// because RFC 8489 keeps it as the baseline and most deployed libraries
	// implement only that.
	m.AddMessageIntegritySHA256(key)
	m.AddMessageIntegrity(key)
	m.AddFingerprint()

	return &udpProbe{
		port:    port,
		txid:    tx,
		request: m.Encode(),
		result:  UDPResult{Port: port, Verdict: UDPNoResponse},
	}, nil
}

func (p *UDPProber) send(conn *net.UDPConn, addr netip.Addr, pr *udpProbe) {
	dst := net.UDPAddrFromAddrPort(netip.AddrPortFrom(addr, uint16(pr.port)))
	if pr.sentAt.IsZero() {
		pr.sentAt = time.Now()
	}
	_, _ = conn.WriteToUDP(pr.request, dst)
}

// readLoop collects responses until every probe is answered or time runs out,
// retransmitting unanswered probes on the way.
func (p *UDPProber) readLoop(conn *net.UDPConn, addr netip.Addr, byTx map[stun.TxID]*udpProbe, key []byte, deadline time.Time) {
	start := time.Now()
	buf := make([]byte, 1500)
	nextRetransmit := 0
	outstanding := len(byTx)

	for outstanding > 0 && time.Now().Before(deadline) {
		wake := deadline
		if nextRetransmit < len(retransmits) {
			if t := start.Add(retransmits[nextRetransmit]); t.Before(wake) {
				wake = t
			}
		}
		_ = conn.SetReadDeadline(wake)

		n, from, err := conn.ReadFromUDP(buf)
		if err != nil {
			// A read deadline elapsed: either a retransmit is due, or the
			// whole batch is finished.
			if nextRetransmit < len(retransmits) && !time.Now().Before(start.Add(retransmits[nextRetransmit])) {
				for _, pr := range byTx {
					if !pr.done {
						p.send(conn, addr, pr)
					}
				}
				nextRetransmit++
			}
			continue
		}

		if pr := p.match(buf[:n], from, addr, byTx, key); pr != nil {
			outstanding--
		}
	}
}

// match validates a datagram and, if it answers an outstanding probe, records
// the result. It returns the probe it completed, or nil.
func (p *UDPProber) match(datagram []byte, from *net.UDPAddr, addr netip.Addr, byTx map[stun.TxID]*udpProbe, key []byte) *udpProbe {
	if !stun.Looks(datagram) {
		return nil
	}
	msg, err := stun.Decode(datagram)
	if err != nil {
		return nil
	}
	pr, ok := byTx[msg.TxID]
	if !ok || pr.done {
		return nil
	}

	// The response must come from the address and port that was probed. A
	// reply from somewhere else says nothing about that port's reachability.
	fromAP := from.AddrPort()
	if fromAP.Addr().Unmap() != addr || int(fromAP.Port()) != pr.port {
		return nil
	}

	// Authentication is what makes the verdict meaningful. Without it, any
	// party able to guess or observe the transaction id could assert that a
	// port is reachable when it is not.
	if !msg.CheckMessageIntegrity(key) {
		pr.result.Detail = "a response arrived but failed authentication"
		return nil
	}
	if !msg.CheckFingerprint() {
		return nil
	}
	if msg.Type != stun.BindingResponse {
		if code, reason, ok := msg.ErrorCode(); ok {
			pr.done = true
			pr.result.Verdict = UDPNoResponse
			pr.result.Detail = fmt.Sprintf("the client rejected the probe: %d %s", code, reason)
			return pr
		}
		return nil
	}

	pr.done = true
	pr.result.Verdict = UDPOpen
	pr.result.RespondedFrom = fromAP.String()
	pr.result.RTTMS = int(time.Since(pr.sentAt).Milliseconds())
	return pr
}

// SummaryUDP explains a UDP verdict, so every client says the same thing.
func SummaryUDP(v Verdict) string {
	switch v {
	case UDPOpen:
		return "Unsolicited inbound UDP reaches you. Search results will arrive."
	case UDPNoResponse:
		return "No reply to an unsolicited datagram. If your client implements " +
			"the DROP UDP responder, inbound UDP is being blocked and search " +
			"results will not arrive."
	default:
		return "The test could not be completed. This is a problem at the " +
			"server, not with your connection."
	}
}
