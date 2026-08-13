// Package probe performs the inbound reachability tests.
package probe

import (
	"bufio"
	"context"
	"errors"
	"io"
	"net"
	"net/netip"
	"strings"
	"sync"
	"syscall"
	"time"
)

// Verdict is the outcome of probing one port.
type Verdict string

const (
	// Open: connected and the nonce came back correct. Active mode works.
	Open Verdict = "open"
	// Occupied: connected, but nothing answered the challenge correctly.
	// Something is listening and it is not this client -- usually the wrong
	// port, or a forward pointing at a different host on the LAN.
	Occupied Verdict = "occupied"
	// Refused: RST. The host is reachable and nothing is listening. The client
	// is not bound, or the forward is missing -- but nothing is dropping.
	Refused Verdict = "refused"
	// Filtered: timeout. A firewall or NAT is silently dropping. This is the
	// port-forwarding case.
	Filtered Verdict = "filtered"
	// Error: the probe could not be carried out; not a statement about the
	// client. Reported separately so a server-side fault is never shown to a
	// user as "your firewall is blocking".
	Error Verdict = "error"
)

// The challenge exchange. The server speaks first with one LF-terminated
// line; the client answers with one line and closes.
const (
	challengePrefix = "DROP/1 CHALLENGE "
	responsePrefix  = "DROP/1 RESPONSE "

	// maxLine caps both directions. The specification fixes this at 128 bytes
	// so that neither side can be made to buffer on a hostile peer.
	maxLine = 128
)

// TCPResult is the outcome for one port.
type TCPResult struct {
	Port    int     `json:"port"`
	Verdict Verdict `json:"verdict"`
	RTTMS   int     `json:"rtt_ms,omitempty"`
	Detail  string  `json:"detail,omitempty"`
}

// TCPProber runs inbound TCP probes.
type TCPProber struct {
	// LocalAddr is the address probes are sent from. Binding it explicitly
	// matters on a multi-homed host: the client is told which address to
	// expect, and an unbound socket may pick a different one.
	LocalAddr netip.Addr
	// Timeout bounds a single probe end to end.
	Timeout time.Duration
}

// ProbeTCP connects to addr:port, issues the challenge, and classifies the
// result.
//
// The nonce is mandatory. Without it "connect succeeded" would be a port scan
// result; with it the server only ever reports that the requesting client
// itself answered.
func (p *TCPProber) ProbeTCP(ctx context.Context, addr netip.Addr, port int, nonce string) TCPResult {
	res := TCPResult{Port: port}

	ctx, cancel := context.WithTimeout(ctx, p.Timeout)
	defer cancel()

	dialer := &net.Dialer{}
	if p.LocalAddr.IsValid() {
		dialer.LocalAddr = &net.TCPAddr{IP: p.LocalAddr.AsSlice()}
	}

	network := "tcp4"
	if addr.Is6() {
		network = "tcp6"
	}
	target := netip.AddrPortFrom(addr, uint16(port)).String()

	start := time.Now()
	conn, err := dialer.DialContext(ctx, network, target)
	if err != nil {
		res.Verdict = classifyDialError(ctx, err)
		if res.Verdict == Error {
			res.Detail = err.Error()
		}
		return res
	}
	defer conn.Close()

	res.RTTMS = int(time.Since(start).Milliseconds())

	// Anything that connected but does not complete the exchange is
	// "occupied": something is listening there, but it is not this client.
	if deadline, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(deadline)
	}

	if _, err := io.WriteString(conn, challengePrefix+nonce+"\n"); err != nil {
		res.Verdict = Occupied
		res.Detail = "connected but the challenge could not be sent"
		return res
	}

	line, err := readLine(conn, maxLine)
	if err != nil {
		res.Verdict = Occupied
		if errors.Is(err, errLineTooLong) {
			res.Detail = "response exceeded the line limit"
		} else {
			res.Detail = "connected but no response to the challenge"
		}
		return res
	}

	got, ok := strings.CutPrefix(line, responsePrefix)
	if !ok {
		res.Verdict = Occupied
		res.Detail = "connected but the response was not a DROP response"
		return res
	}
	if got != nonce {
		res.Verdict = Occupied
		res.Detail = "connected but the challenge was answered incorrectly"
		return res
	}

	res.Verdict = Open
	return res
}

// classifyDialError turns a dial failure into a verdict.
//
// The refused/filtered distinction is the diagnostic payload of the whole
// service: refused means the packets arrive and nothing is listening, which is
// almost always fixable locally, while filtered means something on the path is
// dropping them, which is the port-forwarding case. Collapsing the two into
// "failed" would throw away the only part users can act on.
func classifyDialError(ctx context.Context, err error) Verdict {
	if errors.Is(err, context.DeadlineExceeded) || errors.Is(ctx.Err(), context.DeadlineExceeded) {
		return Filtered
	}
	if errors.Is(err, syscall.ECONNREFUSED) {
		return Refused
	}
	// A timeout can also surface as a net.Error rather than the context error,
	// depending on where the deadline fired.
	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		return Filtered
	}
	// Host- and network-unreachable mean an ICMP error came back, so packets
	// are reaching the network and being rejected: the same actionable
	// category as a refusal, and definitely not a silent drop.
	if errors.Is(err, syscall.EHOSTUNREACH) || errors.Is(err, syscall.ENETUNREACH) {
		return Refused
	}
	if errors.Is(err, syscall.ECONNRESET) {
		return Refused
	}
	return Error
}

var errLineTooLong = errors.New("line too long")

// readLine reads one LF-terminated line, refusing anything longer than limit.
// A hostile or broken peer must not be able to make the server buffer.
func readLine(r io.Reader, limit int) (string, error) {
	br := bufio.NewReaderSize(r, limit+1)
	line, err := br.ReadString('\n')
	if len(line) > limit {
		return "", errLineTooLong
	}
	if err != nil {
		// A peer that closed after sending an unterminated line still gave us
		// something worth classifying.
		if errors.Is(err, io.EOF) && line != "" {
			return strings.TrimRight(line, "\r\n"), nil
		}
		return "", err
	}
	return strings.TrimRight(line, "\r\n"), nil
}

// ProbeTCPAll probes every port concurrently and returns results in the order
// the ports were given.
//
// Concurrency is what keeps a multi-port check within the deadline: four
// filtered ports probed in sequence would take four timeouts and blow through
// the 15 second cap the specification sets.
func (p *TCPProber) ProbeTCPAll(ctx context.Context, addr netip.Addr, ports []int, nonceFor func(port int) string) []TCPResult {
	results := make([]TCPResult, len(ports))
	var wg sync.WaitGroup
	for i, port := range ports {
		wg.Add(1)
		go func(i, port int) {
			defer wg.Done()
			results[i] = p.ProbeTCP(ctx, addr, port, nonceFor(port))
		}(i, port)
	}
	wg.Wait()
	return results
}

// Summary renders a verdict as a short explanation, so that every client shows
// the user the same wording.
func (v Verdict) Summary() string {
	switch v {
	case Open:
		return "Reachable. Active mode works on this port."
	case Occupied:
		return "Something is listening on that port, but it is not this client. " +
			"Check that you nominated the right port and that any port forward " +
			"points at this machine."
	case Refused:
		return "The connection was refused. Packets reach your network and " +
			"nothing is listening: check that the client is bound to that port " +
			"and that a port forward exists. Nothing is being dropped."
	case Filtered:
		return "The connection timed out. A firewall or NAT is silently " +
			"dropping inbound connections; a port forward is the usual remedy."
	default:
		return "The test could not be completed. This is a problem at the " +
			"server, not with your connection."
	}
}

func (v Verdict) String() string { return string(v) }
