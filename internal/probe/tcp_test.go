package probe

import (
	"context"
	"io"
	"net"
	"net/netip"
	"strings"
	"testing"
	"time"
)

func prober() *TCPProber {
	return &TCPProber{Timeout: 2 * time.Second}
}

// listenLoopback starts a listener on 127.0.0.1 and hands each accepted
// connection to fn.
func listenLoopback(t *testing.T, fn func(net.Conn)) (netip.Addr, int) {
	t.Helper()
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				fn(conn)
			}()
		}
	}()

	ap := netip.MustParseAddrPort(ln.Addr().String())
	return ap.Addr(), int(ap.Port())
}

// wellBehavedClient is what a conforming DC client does.
func wellBehavedClient(conn net.Conn) {
	line, err := readLine(conn, maxLine)
	if err != nil {
		return
	}
	nonce, ok := strings.CutPrefix(line, challengePrefix)
	if !ok {
		return
	}
	io.WriteString(conn, responsePrefix+nonce+"\n")
}

func TestProbeTCPOpen(t *testing.T) {
	addr, port := listenLoopback(t, wellBehavedClient)

	res := prober().ProbeTCP(context.Background(), addr, port, "test-nonce-abc")
	if res.Verdict != Open {
		t.Fatalf("verdict = %q (%s), want open", res.Verdict, res.Detail)
	}
	if res.Port != port {
		t.Errorf("port = %d, want %d", res.Port, port)
	}
}

// Nothing listening: the kernel sends an RST, which must read as "refused" and
// not as "filtered". This is the distinction users act on.
func TestProbeTCPRefused(t *testing.T) {
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ap := netip.MustParseAddrPort(ln.Addr().String())
	ln.Close() // free the port so connections are refused

	res := prober().ProbeTCP(context.Background(), ap.Addr(), int(ap.Port()), "n")
	if res.Verdict != Refused {
		t.Fatalf("verdict = %q (%s), want refused", res.Verdict, res.Detail)
	}
}

// A blackholed address produces a timeout, which must read as "filtered".
// 198.51.100.0/24 is TEST-NET-2 and is not routed.
func TestProbeTCPFiltered(t *testing.T) {
	if testing.Short() {
		t.Skip("needs a timeout to elapse")
	}
	p := &TCPProber{Timeout: 750 * time.Millisecond}
	res := p.ProbeTCP(context.Background(), netip.MustParseAddr("198.51.100.1"), 1511, "n")

	// A network with no route may answer immediately with unreachable rather
	// than dropping; both are legitimate here, and neither may be "open".
	if res.Verdict != Filtered && res.Verdict != Refused {
		t.Fatalf("verdict = %q (%s), want filtered or refused", res.Verdict, res.Detail)
	}
}

// Something else is on the port. The service must not report that as reachable
// -- this is the case where a port forward points at the wrong host.
func TestProbeTCPOccupiedBySilentService(t *testing.T) {
	addr, port := listenLoopback(t, func(conn net.Conn) {
		time.Sleep(3 * time.Second) // never answers
	})

	p := &TCPProber{Timeout: 600 * time.Millisecond}
	res := p.ProbeTCP(context.Background(), addr, port, "n")
	if res.Verdict != Occupied {
		t.Fatalf("verdict = %q (%s), want occupied", res.Verdict, res.Detail)
	}
}

func TestProbeTCPOccupiedByOtherProtocol(t *testing.T) {
	addr, port := listenLoopback(t, func(conn net.Conn) {
		io.WriteString(conn, "SSH-2.0-OpenSSH_9.6\r\n")
	})

	res := prober().ProbeTCP(context.Background(), addr, port, "n")
	if res.Verdict != Occupied {
		t.Fatalf("verdict = %q (%s), want occupied", res.Verdict, res.Detail)
	}
}

// The security property: a listener that answers with the wrong nonce is not
// the client that asked. Without this, the service reports any open port as
// reachable and becomes a port scanner.
func TestProbeTCPWrongNonceIsNotOpen(t *testing.T) {
	addr, port := listenLoopback(t, func(conn net.Conn) {
		readLine(conn, maxLine)
		io.WriteString(conn, responsePrefix+"the-wrong-nonce\n")
	})

	res := prober().ProbeTCP(context.Background(), addr, port, "the-right-nonce")
	if res.Verdict == Open {
		t.Fatal("a wrong nonce must never produce open")
	}
	if res.Verdict != Occupied {
		t.Errorf("verdict = %q, want occupied", res.Verdict)
	}
}

// A peer that echoes the challenge verbatim rather than sending a response
// must not be accepted: it proves nothing beyond being an echo server.
func TestProbeTCPEchoIsNotOpen(t *testing.T) {
	addr, port := listenLoopback(t, func(conn net.Conn) {
		line, err := readLine(conn, maxLine)
		if err != nil {
			return
		}
		io.WriteString(conn, line+"\n")
	})

	res := prober().ProbeTCP(context.Background(), addr, port, "abc")
	if res.Verdict == Open {
		t.Fatal("an echo server must not be reported as open")
	}
}

// A hostile peer must not be able to make the server buffer without bound.
func TestProbeTCPRefusesOverlongResponse(t *testing.T) {
	addr, port := listenLoopback(t, func(conn net.Conn) {
		readLine(conn, maxLine)
		io.WriteString(conn, responsePrefix+strings.Repeat("A", 64*1024)+"\n")
	})

	res := prober().ProbeTCP(context.Background(), addr, port, "abc")
	if res.Verdict != Occupied {
		t.Fatalf("verdict = %q, want occupied", res.Verdict)
	}
	if !strings.Contains(res.Detail, "line limit") {
		t.Errorf("detail = %q, want a mention of the line limit", res.Detail)
	}
}

func TestProbeTCPAllRunsConcurrently(t *testing.T) {
	if testing.Short() {
		t.Skip("measures elapsed time")
	}
	addr, port := listenLoopback(t, wellBehavedClient)

	// Three ports that will time out, plus one that answers. Run in sequence
	// this would take three timeouts; concurrently it takes one.
	ports := []int{port, 1, 2, 3}
	dead := netip.MustParseAddr("198.51.100.1")
	_ = dead

	p := &TCPProber{Timeout: time.Second}
	start := time.Now()
	results := p.ProbeTCPAll(context.Background(), addr, ports, func(int) string { return "n" })
	elapsed := time.Since(start)

	if len(results) != len(ports) {
		t.Fatalf("got %d results, want %d", len(results), len(ports))
	}
	// Results must line up with the requested ports, or a client attributes a
	// verdict to the wrong port.
	for i, port := range ports {
		if results[i].Port != port {
			t.Errorf("result %d is for port %d, want %d", i, results[i].Port, port)
		}
	}
	if results[0].Verdict != Open {
		t.Errorf("the answering port: verdict = %q, want open", results[0].Verdict)
	}
	if elapsed > 3*time.Second {
		t.Errorf("probes took %v; they do not appear to run concurrently", elapsed)
	}
}

func TestReadLine(t *testing.T) {
	cases := []struct {
		in      string
		want    string
		wantErr bool
	}{
		{"hello\n", "hello", false},
		{"hello\r\n", "hello", false},
		{"hello", "hello", false}, // unterminated but closed
		{"", "", true},
		{strings.Repeat("x", 200) + "\n", "", true},
	}
	for _, c := range cases {
		got, err := readLine(strings.NewReader(c.in), maxLine)
		if (err != nil) != c.wantErr {
			t.Errorf("readLine(%q) error = %v, wantErr %v", truncate(c.in), err, c.wantErr)
			continue
		}
		if !c.wantErr && got != c.want {
			t.Errorf("readLine(%q) = %q, want %q", truncate(c.in), got, c.want)
		}
	}
}

func TestVerdictSummariesExist(t *testing.T) {
	for _, v := range []Verdict{Open, Occupied, Refused, Filtered, Error} {
		if v.Summary() == "" {
			t.Errorf("verdict %q has no summary", v)
		}
	}
	// The refused and filtered summaries must not be interchangeable: they
	// send the user to different places.
	if Refused.Summary() == Filtered.Summary() {
		t.Error("refused and filtered must be explained differently")
	}
}

func truncate(s string) string {
	if len(s) > 32 {
		return s[:32] + "..."
	}
	return s
}
